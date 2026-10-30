//! The controller: brings the network up, serves its API, then keeps the network configured as
//! interfaces appear and the DNS override changes.

use std::convert::Infallible;
use std::future;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use libserviced::activation::ActivatedSocket;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::notify;
use network_controller::network::network_controller_server::NetworkControllerServer;
use tokio::time::Instant;
use tonic::transport::Channel;
use tonic::transport::Server;

use crate::interfaces::Interfaces;
use crate::link;
use crate::link::Netlink;
use crate::link_events::LinkEvent;
use crate::link_events::LinkEvents;
use crate::link_events::LinkState;
use crate::network_service::NetworkService;
use crate::options::Options;
use crate::persisted_state;
use crate::shared::Shared;

/// Configures the network and keeps it configured, serving `hardened.network.v1` on `api` to
/// the callers `serviced` identifies; notifies serviced once [`configure`] returns. Returns only
/// on an error.
pub async fn run(
    options: Options,
    api: ActivatedSocket,
    serviced: ServicedClient<Channel>,
) -> anyhow::Result<Infallible> {
    let shared = Arc::new(Shared::new(
        options.resolv_conf.clone(),
        options.state_file.clone(),
    ));
    match persisted_state::load(&options.state_file) {
        Ok(dns) => shared.set_dns_override(dns),
        Err(error) => tracing::error!(error = format!("{error:#}"), "ignoring the persisted state"),
    }
    let service = NetworkService::new(Arc::clone(&shared));
    let router = Server::builder().add_service(NetworkControllerServer::new(service));
    let serving = async {
        libserviced::authorization::serve(router, api, serviced, future::pending())
            .await
            .context("serving the API")?;
        Err(anyhow::anyhow!("the API stopped serving"))
    };
    let configuring = async {
        configure(&options, &shared).await?;
        shared.log();
        notify::ready().context("notifying serviced of the readiness")?;
        future::pending().await
    };
    tokio::select! {
        result = serving => result,
        result = configuring => result,
    }
}

/// Brings up the network. Returns once at least one interface got a lease or all attempts timed
/// out; leases keep being renewed and new interfaces configured by background tasks, which
/// share `shared`.
async fn configure(options: &Options, shared: &Arc<Shared>) -> anyhow::Result<()> {
    let netlink = Netlink::connect()?;
    netlink.set_up("lo").await?;

    // resolv.conf exists even if DHCP never succeeds.
    shared.refresh();

    let started = Instant::now();
    // Subscribed before listing the links, so that none appears unseen in between.
    let mut events = LinkEvents::subscribe().context("subscribing to link events")?;
    let links = wait_for_interfaces(&netlink, &mut events, &options.sysfs_net);
    let links = match tokio::time::timeout(options.link_timeout, links).await {
        Ok(links) => links,
        Err(_) => {
            tracing::warn!(
                "no physical Ethernet interface after {:?}",
                options.link_timeout
            );
            Vec::new()
        }
    };
    let mut interfaces = Interfaces::new(Arc::clone(shared), options.sysfs_net.clone());
    let changes = interfaces.reconcile(&links);
    interfaces.apply(&netlink, changes).await;
    tokio::spawn(watch_interfaces(interfaces, netlink, events));

    let mut bound = shared.bound.subscribe();
    let deadline = started + options.lease_timeout;
    if tokio::time::timeout_at(deadline, bound.wait_for(|&count| count > 0))
        .await
        .is_err()
    {
        tracing::warn!(
            "no DHCP lease after {:?}, continuing without network",
            options.lease_timeout
        );
    }
    Ok(())
}

/// The physical Ethernet interfaces, sorted by name, once there is at least one; `events` must
/// be subscribed already.
#[must_use]
async fn wait_for_interfaces(
    netlink: &Netlink,
    events: &mut LinkEvents,
    sysfs: &Path,
) -> Vec<LinkState> {
    let mut list = true;
    loop {
        if list {
            let links = physical_links(netlink, sysfs).await;
            if !links.is_empty() {
                return links;
            }
        }
        list = match events.next().await {
            Ok(LinkEvent::Changed(link)) if link::is_physical_ethernet(sysfs, &link.name) => {
                return vec![link];
            }
            Ok(LinkEvent::Lost) => true,
            Ok(_) => false,
            Err(err) => {
                tracing::error!("link events: {err}");
                // Until the caller's timeout.
                return future::pending().await;
            }
        };
    }
}

/// The physical Ethernet interfaces, sorted by name.
#[must_use]
async fn physical_links(netlink: &Netlink, sysfs: &Path) -> Vec<LinkState> {
    match netlink.links().await {
        Ok(links) => {
            let mut links: Vec<LinkState> = links
                .into_iter()
                .filter(|link| link::is_physical_ethernet(sysfs, &link.name))
                .collect();
            links.sort_by(|a, b| a.name.cmp(&b.name));
            links
        }
        Err(err) => {
            tracing::warn!("listing the links: {err}");
            Vec::new()
        }
    }
}

/// Keeps DHCP running on the physical Ethernet interfaces after the initial configuration:
/// starts it on those appearing (late driver probe, hot-plug, re-plug), stops it on those
/// removed.
async fn watch_interfaces(mut interfaces: Interfaces, netlink: Netlink, mut events: LinkEvents) {
    loop {
        let changes = match events.next().await {
            Ok(LinkEvent::Lost) => match netlink.links().await {
                Ok(links) => interfaces.reconcile(&links),
                Err(err) => {
                    tracing::warn!("listing the links: {err}");
                    continue;
                }
            },
            Ok(event) => interfaces.changes(&event),
            Err(err) => return tracing::error!("link events: {err}, no longer watching"),
        };
        interfaces.apply(&netlink, changes).await;
    }
}

#[cfg(test)]
mod tests {
    /// End-to-end test against DHCP servers on veth peers. The client side runs in a user +
    /// network namespace (`unshare -rn`); the servers run in a nested network namespace of their
    /// own, as a server sharing the client's namespace would see its own address as the source of
    /// the client's packets (Linux picks any local address when the interface has none).
    mod netns {
        use std::env;
        use std::fmt::Write as _;
        use std::fs;
        use std::net::IpAddr;
        use std::net::Ipv4Addr;
        use std::process::Child;
        use std::process::Command;
        use std::time::Duration;

        use netlink_packet_core::NLM_F_CREATE;
        use netlink_packet_core::NLM_F_DUMP;
        use netlink_packet_core::NLM_F_EXCL;
        use netlink_packet_route::AddressFamily;
        use netlink_packet_route::RouteNetlinkMessage;
        use netlink_packet_route::address::AddressAttribute;
        use netlink_packet_route::address::AddressMessage;
        use netlink_packet_route::link::InfoData;
        use netlink_packet_route::link::InfoKind;
        use netlink_packet_route::link::InfoVeth;
        use netlink_packet_route::link::LinkAttribute;
        use netlink_packet_route::link::LinkInfo;
        use netlink_packet_route::link::LinkMessage;
        use netlink_packet_route::route::RouteAddress;
        use netlink_packet_route::route::RouteAttribute;
        use netlink_packet_route::route::RouteMessage;
        use netlink_packet_route::route::RouteProtocol;
        use netlink_packet_route::route::RouteScope;
        use network_controller::DnsSettings;
        use tokio::runtime::Runtime;
        use tracing::Level;
        use tracing_subscriber::filter::Targets;
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;

        use super::super::*;
        use crate::dhcp;
        use crate::dhcp::CLIENT_PORT;
        use crate::dhcp::SERVER_PORT;
        use crate::dhcp::tests::reply_to;
        use crate::dhcp_message::Message;
        use crate::dhcp_option::DhcpOption;
        use crate::dhcp_option::MessageType;
        use crate::prefix_len::PrefixLen;

        const TEST: &str = "run::tests::netns::dhcp_end_to_end";
        const SERVER0: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
        const SERVER1: Ipv4Addr = Ipv4Addr::new(10, 43, 0, 1);
        /// Role of the test process: unset (launcher), `client` or `server`.
        const ROLE: &str = "NETWORK_CONTROLLER_TEST_ROLE";

        #[test]
        #[ignore = "needs unprivileged user namespaces (unshare -rn)"]
        fn dhcp_end_to_end() {
            let runtime = || Runtime::new().unwrap();
            match env::var(ROLE).as_deref() {
                Ok("client") => runtime().block_on(client()),
                Ok("server") => runtime().block_on(servers()),
                _ => {
                    let status = rerun(&["--user", "--map-root-user", "--net"], "client")
                        .status()
                        .unwrap();
                    assert!(
                        status.success(),
                        "test inside the namespace failed: {status}"
                    );
                }
            }
        }

        /// This test, run again in new namespaces by `unshare`.
        fn rerun(namespaces: &[&str], role: &str) -> Command {
            let mut command = Command::new("unshare");
            command
                .args(namespaces)
                .arg("--")
                .arg(env::current_exe().unwrap())
                .args(["--ignored", "--exact", "--nocapture", TEST])
                .env(ROLE, role);
            command
        }

        /// Kills the server process when the client side is done.
        struct Servers(Child);

        impl Drop for Servers {
            fn drop(&mut self) {
                let _ = self.0.kill();
                let _ = self.0.wait();
            }
        }

        async fn link(netlink: &Netlink, name: &str) -> Option<LinkMessage> {
            netlink.link_message(name).await.ok()
        }

        async fn index(netlink: &Netlink, name: &str) -> u32 {
            link(netlink, name).await.unwrap().header.index
        }

        /// The replies to the dump `request`.
        async fn dump(netlink: &Netlink, request: RouteNetlinkMessage) -> Vec<RouteNetlinkMessage> {
            netlink.request(request, NLM_F_DUMP).await.unwrap()
        }

        /// The server process: configures the server end of each veth pair once it is moved into
        /// its namespace, then serves forever.
        async fn servers() {
            // A plain /24 with a short lease, renewed during the test.
            let short = tokio::spawn(serve(
                "srv0",
                SERVER0,
                Ipv4Addr::new(10, 42, 0, 10),
                vec![
                    DhcpOption::ServerIdentifier(SERVER0),
                    DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
                    DhcpOption::Router(vec![Ipv4Addr::new(10, 42, 0, 1)]),
                    DhcpOption::DomainNameServer(vec![Ipv4Addr::new(10, 42, 0, 53)]),
                    DhcpOption::DomainName("test.internal".into()),
                    DhcpOption::Hostname("node-1".into()),
                    DhcpOption::InterfaceMtu(1400),
                    DhcpOption::AddressLeaseTime(4),
                ],
            ));
            // A /32 and a gateway outside of it.
            let gcp = tokio::spawn(serve(
                "srv1",
                SERVER1,
                Ipv4Addr::new(10, 43, 0, 10),
                vec![
                    DhcpOption::ServerIdentifier(SERVER1),
                    DhcpOption::SubnetMask(Ipv4Addr::BROADCAST),
                    DhcpOption::Router(vec![Ipv4Addr::new(10, 43, 0, 1)]),
                    DhcpOption::DomainNameServer(vec![Ipv4Addr::new(10, 43, 0, 53)]),
                    DhcpOption::AddressLeaseTime(3600),
                ],
            ));
            let _ = tokio::join!(short, gcp);
        }

        /// A minimal server of address `server` for one client on `ifname`, handing out
        /// `address`; serves again when `ifname` is deleted and created again.
        async fn serve(
            ifname: &str,
            server: Ipv4Addr,
            address: Ipv4Addr,
            options: Vec<DhcpOption>,
        ) {
            let netlink = Netlink::connect().unwrap();
            loop {
                while link(&netlink, ifname).await.is_none() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                netlink.set_up(ifname).await.unwrap();
                let index = index(&netlink, ifname).await;
                let msg = link::address_message(index, server, PrefixLen::new(24).unwrap());
                netlink
                    .request(
                        RouteNetlinkMessage::NewAddress(msg),
                        NLM_F_CREATE | NLM_F_EXCL,
                    )
                    .await
                    .unwrap();
                serve_link(&netlink, ifname, index, address, &options).await;
            }
        }

        /// Serves on `ifname` while it keeps `index`.
        async fn serve_link(
            netlink: &Netlink,
            ifname: &str,
            index: u32,
            address: Ipv4Addr,
            options: &[DhcpOption],
        ) {
            let socket = dhcp::bind(ifname, SERVER_PORT).unwrap();
            let mut buf = vec![0u8; 1500];
            loop {
                let received = socket.recv_from(&mut buf);
                let Ok(received) = tokio::time::timeout(Duration::from_millis(100), received).await
                else {
                    let current = link(netlink, ifname).await.map(|msg| msg.header.index);
                    if current != Some(index) {
                        return;
                    }
                    continue;
                };
                let Ok((len, _)) = received else {
                    // The link went away under the socket.
                    return;
                };
                let Ok(request) = Message::decode(&buf[..len]) else {
                    continue;
                };
                let (kind, target) = match request.options.message_type() {
                    Some(MessageType::Discover) => (MessageType::Offer, Ipv4Addr::BROADCAST),
                    Some(MessageType::Request) if request.ciaddr.is_unspecified() => {
                        (MessageType::Ack, Ipv4Addr::BROADCAST)
                    }
                    Some(MessageType::Request) => (MessageType::Ack, request.ciaddr),
                    _ => continue,
                };
                let reply = reply_to(&request, kind, address, options.to_vec());
                socket.send_to(&reply, (target, CLIENT_PORT)).await.unwrap();
            }
        }

        /// `msg` formatted like a line of `ip route`.
        fn route_line(msg: &RouteMessage) -> String {
            let destination = msg.attributes.iter().find_map(|attr| match attr {
                RouteAttribute::Destination(RouteAddress::Inet(destination)) => Some(destination),
                _ => None,
            });
            let mut line = match destination {
                Some(destination) => {
                    format!("{destination}/{}", msg.header.destination_prefix_length)
                }
                None => "default".to_owned(),
            };
            for attr in &msg.attributes {
                if let RouteAttribute::Gateway(RouteAddress::Inet(gateway)) = attr {
                    write!(line, " via {gateway}").unwrap();
                }
            }
            for attr in &msg.attributes {
                if let RouteAttribute::Priority(metric) = attr {
                    write!(line, " metric {metric}").unwrap();
                }
            }
            if msg.header.scope == RouteScope::Link {
                line.push_str(" scope link");
            }
            line
        }

        /// DHCP routes of `ifname`, formatted like `ip route`.
        async fn routes(netlink: &Netlink, ifname: &str) -> Vec<String> {
            let index = index(netlink, ifname).await;
            let mut request = RouteMessage::default();
            request.header.address_family = AddressFamily::Inet;
            let mut lines = Vec::new();
            for reply in dump(netlink, RouteNetlinkMessage::GetRoute(request)).await {
                let RouteNetlinkMessage::NewRoute(msg) = reply else {
                    continue;
                };
                if msg.header.protocol == RouteProtocol::Dhcp
                    && msg.attributes.contains(&RouteAttribute::Oif(index))
                {
                    lines.push(route_line(&msg));
                }
            }
            lines
        }

        async fn addresses(netlink: &Netlink, ifname: &str) -> Vec<String> {
            let index = index(netlink, ifname).await;
            let request = RouteNetlinkMessage::GetAddress(AddressMessage::default());
            dump(netlink, request)
                .await
                .into_iter()
                .filter_map(|reply| match reply {
                    RouteNetlinkMessage::NewAddress(msg) if msg.header.index == index => Some(msg),
                    _ => None,
                })
                .filter_map(|msg| {
                    msg.attributes.iter().find_map(|attr| match attr {
                        AddressAttribute::Address(IpAddr::V4(address)) => {
                            Some(format!("{address}/{}", msg.header.prefix_len))
                        }
                        _ => None,
                    })
                })
                .collect()
        }

        async fn mtu(netlink: &Netlink, ifname: &str) -> u32 {
            let msg = link(netlink, ifname).await.unwrap();
            msg.attributes
                .iter()
                .find_map(|attr| match attr {
                    LinkAttribute::Mtu(mtu) => Some(*mtu),
                    _ => None,
                })
                .unwrap()
        }

        /// Creates the veth pair `client`-`server`, and moves `server` into the namespace of the
        /// process `pid`.
        async fn add_veth(netlink: &Netlink, client: &str, server: &str, pid: u32) {
            let mut peer = LinkMessage::default();
            peer.attributes.push(LinkAttribute::IfName(server.into()));
            let mut veth = LinkMessage::default();
            veth.attributes.push(LinkAttribute::IfName(client.into()));
            veth.attributes.push(LinkAttribute::LinkInfo(vec![
                LinkInfo::Kind(InfoKind::Veth),
                LinkInfo::Data(InfoData::Veth(InfoVeth::Peer(peer))),
            ]));
            netlink
                .request(
                    RouteNetlinkMessage::NewLink(veth),
                    NLM_F_CREATE | NLM_F_EXCL,
                )
                .await
                .unwrap();
            let mut moved = LinkMessage::default();
            moved.attributes.push(LinkAttribute::IfName(server.into()));
            moved.attributes.push(LinkAttribute::NetNsPid(pid));
            netlink
                .request(RouteNetlinkMessage::SetLink(moved), 0)
                .await
                .unwrap();
        }

        async fn client() {
            let filter: Targets = env::var("RUST_LOG")
                .ok()
                .and_then(|directives| directives.parse().ok())
                .unwrap_or_else(|| Targets::new().with_target("network_controller", Level::DEBUG));
            let _ = tracing_subscriber::registry()
                .with(filter)
                .with(tracing_subscriber::fmt::layer().with_test_writer())
                .try_init();
            // Strict reverse path filtering, as hardened's sysctl defaults: replies arriving
            // before the interface has an address are dropped by the kernel, packet sockets see
            // them.
            for conf in ["all", "default"] {
                fs::write(format!("/proc/sys/net/ipv4/conf/{conf}/rp_filter"), "1").unwrap();
            }

            let netlink = Netlink::connect().unwrap();

            let servers = Servers(rerun(&["--net"], "server").spawn().unwrap());
            let own_netns = fs::read_link("/proc/self/ns/net").unwrap();
            let server_netns = format!("/proc/{}/ns/net", servers.0.id());
            while fs::read_link(&server_netns).is_ok_and(|ns| ns == own_netns) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let run = tempfile::tempdir().unwrap();
            // The veths, as physical Ethernet interfaces.
            let sysfs_net = run.path().join("sys/class/net");
            for name in ["dhcp0", "dhcp1"] {
                fs::create_dir_all(sysfs_net.join(name).join("device")).unwrap();
                fs::write(sysfs_net.join(name).join("type"), "1\n").unwrap();
            }
            let options = Options {
                resolv_conf: run.path().join("resolv.conf"),
                state_file: run.path().join("state.json"),
                sysfs_net,
                link_timeout: Duration::from_secs(1),
                lease_timeout: Duration::from_secs(20),
            };
            let shared = Arc::new(Shared::new(
                options.resolv_conf.clone(),
                options.state_file.clone(),
            ));
            // dhcp0 appears while configure waits for an interface, dhcp1 once it returned:
            // both are found through link notifications.
            let plug = async {
                tokio::time::sleep(Duration::from_millis(200)).await;
                add_veth(&netlink, "dhcp0", "srv0", servers.0.id()).await;
            };
            let (configured, ()) = tokio::join!(configure(&options, &shared), plug);
            configured.unwrap();
            assert_eq!(shared.primary().as_deref(), Some("dhcp0"));
            let primary = "dhcp0";
            let bound = Instant::now();
            add_veth(&netlink, "dhcp1", "srv1", servers.0.id()).await;

            // Wait for both leases.
            let mut leases = shared.bound.subscribe();
            let both = leases.wait_for(|&count| count == 2);
            tokio::time::timeout(Duration::from_secs(20), both)
                .await
                .expect("second lease missing")
                .unwrap();

            // The primary interface has the lowest metric.
            let metrics = |name: &str| {
                if primary == name { 1024 } else { 1124 }
            };
            assert_eq!(addresses(&netlink, "dhcp0").await, ["10.42.0.10/24"]);
            assert_eq!(mtu(&netlink, "dhcp0").await, 1400);
            assert_eq!(
                routes(&netlink, "dhcp0").await,
                [format!("default via 10.42.0.1 metric {}", metrics("dhcp0"))]
            );
            assert_eq!(addresses(&netlink, "dhcp1").await, ["10.43.0.10/32"]);
            let metric = metrics("dhcp1");
            let mut gcp_routes = routes(&netlink, "dhcp1").await;
            gcp_routes.sort();
            assert_eq!(
                gcp_routes,
                [
                    format!("10.43.0.1/32 metric {metric} scope link"),
                    format!("default via 10.43.0.1 metric {metric}"),
                ]
            );
            let resolv_conf = || fs::read_to_string(&options.resolv_conf).unwrap();
            let resolv = resolv_conf();
            assert!(resolv.contains("nameserver 10.42.0.53\n"), "{resolv}");
            assert!(resolv.contains("nameserver 10.43.0.53\n"), "{resolv}");
            assert!(resolv.contains("search test.internal\n"), "{resolv}");

            shared.set_dns_override(DnsSettings {
                name_servers: vec![IpAddr::from([192, 0, 2, 53])],
                ..DnsSettings::default()
            });
            let overridden =
                "# Generated by network-controller.\nnameserver 192.0.2.53\nsearch test.internal\n";
            tokio::time::sleep(Duration::from_millis(100)).await;
            assert_eq!(resolv_conf(), overridden);

            // The 4 s lease of dhcp0 outlives its expiry only if it is renewed.
            tokio::time::sleep_until(bound + Duration::from_secs(9)).await;
            assert_eq!(
                addresses(&netlink, "dhcp0").await,
                ["10.42.0.10/24"],
                "lease not renewed"
            );
            assert_eq!(routes(&netlink, "dhcp0").await.len(), 1);
            assert_eq!(resolv_conf(), overridden, "renewals keep the override");

            // dhcp1 unplugged: its lease is forgotten. Plugged again (a new index): it leases
            // again, ranked after dhcp0, which stays the primary interface.
            let old_index = index(&netlink, "dhcp1").await;
            let mut unplug = LinkMessage::default();
            unplug.header.index = old_index;
            netlink
                .request(RouteNetlinkMessage::DelLink(unplug), 0)
                .await
                .unwrap();
            let one = leases.wait_for(|&count| count == 1);
            tokio::time::timeout(Duration::from_secs(5), one)
                .await
                .expect("the lease of the removed interface is still counted")
                .unwrap();
            assert_eq!(shared.primary().as_deref(), Some("dhcp0"));
            add_veth(&netlink, "dhcp1", "srv1", servers.0.id()).await;
            assert_ne!(index(&netlink, "dhcp1").await, old_index);
            let both = leases.wait_for(|&count| count == 2);
            tokio::time::timeout(Duration::from_secs(20), both)
                .await
                .expect("no lease after the re-plug")
                .unwrap();
            assert_eq!(shared.primary().as_deref(), Some("dhcp0"));
            assert_eq!(addresses(&netlink, "dhcp1").await, ["10.43.0.10/32"]);
            // Rank 2: dhcp0 got 0, dhcp1 before its removal 1.
            let metric = 1224;
            let mut gcp_routes = routes(&netlink, "dhcp1").await;
            gcp_routes.sort();
            assert_eq!(
                gcp_routes,
                [
                    format!("10.43.0.1/32 metric {metric} scope link"),
                    format!("default via 10.43.0.1 metric {metric}"),
                ]
            );
        }
    }
}

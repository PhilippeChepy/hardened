//! Network configuration: loopback, DHCPv4 on every physical Ethernet interface (with lease
//! renewal in the background) and IPv6 SLAAC left to the kernel.
//!
//! dust-init writes `/run/hardened/resolv.conf` and `/run/hardened/hosts`, which `/etc/resolv.conf` and
//! `/etc/hosts` on the read-only root symlink to.

mod dhcp;
mod dns;
mod link;
mod raw;

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::time::Instant;

use self::dhcp::{Client, Identity, Lease, Outcome};
use self::link::{Link, Netlink};
use self::raw::RawSocket;
use crate::settings::DnsSettings;
use crate::types::Hostname;

/// Where the files `/etc/{resolv.conf,hosts,hostname}` point to.
pub const RUNTIME_DIR: &str = "/run/hardened";

/// Result of the initial network configuration.
#[derive(Debug, Clone, Default)]
pub struct NetworkState {
    /// Interfaces DHCP runs on: leased ones first in the order they got their lease (the first
    /// one is the primary interface), then the others.
    pub interfaces: Vec<InterfaceState>,
    /// The nameservers written to `resolv.conf`.
    pub nameservers: Vec<IpAddr>,
    /// Hostname offered through DHCP (option 12) on the primary interface, if any.
    pub dhcp_hostname: Option<Hostname>,
}

#[derive(Debug, Clone)]
pub struct InterfaceState {
    pub name: String,
    /// `None` while DHCP has not obtained a lease.
    pub lease: Option<LeaseInfo>,
}

/// The configuration an interface got from DHCP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseInfo {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
    pub mtu: Option<u16>,
}

/// Brings up the network. Returns once at least one interface got a lease or all attempts timed
/// out; leases keep being renewed by background tasks. Must run within a tokio runtime; it
/// neither blocks the runtime nor spawns processes.
pub async fn configure() -> anyhow::Result<NetworkState> {
    let (state, shared) = configure_with(Options::default()).await?;
    *ACTIVE.lock().unwrap_or_else(PoisonError::into_inner) = Some(shared);
    Ok(state)
}

/// Replaces the nameservers and search domains learned through DHCP with those of `settings.dns`
/// (each list when not empty), known only once user-data is fetched. `resolv.conf` is rewritten
/// right away and keeps the override across renewals.
pub fn set_dns_override(dns: DnsSettings) -> io::Result<()> {
    let active = ACTIVE.lock().unwrap_or_else(PoisonError::into_inner).clone();
    match active {
        Some(shared) => shared.set_dns_override(dns),
        // Networking was not configured: there is nothing else to resolve with.
        None => {
            let (nameservers, search) = resolver_config(&dns, std::iter::empty());
            dns::write_atomic(
                Path::new(RUNTIME_DIR),
                "resolv.conf",
                &dns::render_resolv_conf(&nameservers, &search),
            )
        }
    }
}

/// The network configured by [`configure`].
static ACTIVE: Mutex<Option<Arc<Shared>>> = Mutex::new(None);

/// Writes `/run/hardened/hosts` for `hostname`.
pub fn write_hosts(hostname: &Hostname) -> io::Result<()> {
    write_hosts_in(Path::new(RUNTIME_DIR), hostname)
}

fn write_hosts_in(dir: &Path, hostname: &Hostname) -> io::Result<()> {
    dns::write_atomic(dir, "hosts", &dns::render_hosts(hostname))
}

/// Metric of the primary interface's routes; other interfaces get [`METRIC_STEP`] more per rank so
/// that the primary default route wins and secondary ones never replace each other.
const BASE_METRIC: u32 = 1024;
const METRIC_STEP: u32 = 100;

/// How long to wait for the carrier after bringing an interface up before starting DHCP anyway.
const CARRIER_TIMEOUT: Duration = Duration::from_secs(5);

/// How often to look for interfaces appearing after boot (late driver probe, hotplug).
const DISCOVERY_INTERVAL: Duration = Duration::from_secs(5);

/// Which interfaces to run DHCP on.
#[derive(Debug, Clone)]
enum Interfaces {
    /// Physical Ethernet interfaces of a `/sys/class/net`, including ones appearing later.
    Discover(PathBuf),
    /// Exactly these.
    #[cfg_attr(not(test), allow(dead_code))]
    Fixed(Vec<String>),
}

#[derive(Debug, Clone)]
struct Options {
    runtime_dir: PathBuf,
    interfaces: Interfaces,
    /// Bound on the wait for a first interface to show up.
    link_timeout: Duration,
    /// Bound on the wait for a first lease.
    lease_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            runtime_dir: RUNTIME_DIR.into(),
            interfaces: Interfaces::Discover("/sys/class/net".into()),
            link_timeout: Duration::from_secs(10),
            lease_timeout: Duration::from_secs(30),
        }
    }
}

async fn configure_with(options: Options) -> anyhow::Result<(NetworkState, Arc<Shared>)> {
    let netlink = Netlink::connect()?;
    netlink.set_up("lo").await?;

    let shared = Arc::new(Shared::new(options.runtime_dir.clone()));
    // resolv.conf exists even if DHCP never succeeds.
    if let Err(err) = shared.write_resolv_conf() {
        tracing::error!("writing resolv.conf: {err}");
    }

    let started = Instant::now();
    let names = match &options.interfaces {
        Interfaces::Fixed(names) => names.clone(),
        Interfaces::Discover(sysfs) => wait_for_interfaces(sysfs, options.link_timeout).await,
    };
    if names.is_empty() {
        tracing::warn!("no physical Ethernet interface after {:?}", options.link_timeout);
    }
    for name in &names {
        start_interface(&shared, &netlink, name).await;
    }
    if let Interfaces::Discover(sysfs) = options.interfaces {
        tokio::spawn(watch_interfaces(
            Arc::clone(&shared),
            netlink,
            sysfs,
            names.into_iter().collect(),
        ));
    }

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
    Ok((shared.snapshot(), shared))
}

/// Polls `sysfs` until a physical Ethernet interface shows up or `timeout` elapses.
async fn wait_for_interfaces(sysfs: &Path, timeout: Duration) -> Vec<String> {
    let deadline = Instant::now() + timeout;
    loop {
        match link::physical_ethernet(sysfs) {
            Ok(names) if !names.is_empty() => return names,
            Ok(_) => {}
            Err(err) => tracing::warn!("listing {}: {err}", sysfs.display()),
        }
        if Instant::now() >= deadline {
            return Vec::new();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Starts DHCP on interfaces appearing after the initial configuration.
async fn watch_interfaces(shared: Arc<Shared>, netlink: Netlink, sysfs: PathBuf, mut known: BTreeSet<String>) {
    loop {
        tokio::time::sleep(DISCOVERY_INTERVAL).await;
        let Ok(names) = link::physical_ethernet(&sysfs) else {
            continue;
        };
        for name in names {
            if known.insert(name.clone()) {
                tracing::info!("new interface {name}");
                start_interface(&shared, &netlink, &name).await;
            }
        }
    }
}

/// Brings `name` up and spawns its DHCP client.
async fn start_interface(shared: &Arc<Shared>, netlink: &Netlink, name: &str) {
    let link = match netlink.link(name).await {
        Ok(link) => link,
        Err(err) => return tracing::error!("{err:#}"),
    };
    if let Err(err) = netlink.set_up(name).await {
        return tracing::error!("{err:#}");
    }
    shared.add_interface(name);
    tokio::spawn(run_dhcp(Arc::clone(shared), netlink.clone(), link));
}

/// Runs DHCP on `link` forever, applying leases as they come and go.
async fn run_dhcp(shared: Arc<Shared>, netlink: Netlink, link: Link) {
    if !netlink.wait_for_carrier(&link.name, CARRIER_TIMEOUT).await {
        tracing::warn!(interface = %link.name, "no carrier after {CARRIER_TIMEOUT:?}, trying DHCP anyway");
    }
    let socket = loop {
        match dhcp::bind(&link.name) {
            Ok(socket) => break socket,
            Err(err) => {
                tracing::error!(interface = %link.name, "DHCP socket: {err}");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    };
    let client = Client::new(socket, Identity { mac: link.mac }, link.name.clone());
    let mut rank = None;
    loop {
        let mut lease = acquire(&client, &link).await;
        let rank = *rank.get_or_insert_with(|| shared.next_rank());
        let metric = BASE_METRIC + rank * METRIC_STEP;
        tracing::info!(
            interface = %link.name,
            "DHCP: bound to {}/{} from {} ({})",
            lease.address,
            lease.prefix_len,
            lease.server,
            if rank == 0 { "primary" } else { "secondary" },
        );
        apply_lease(&netlink, &link, None, &lease, metric).await;
        shared.bind(rank, &link.name, lease.clone());
        loop {
            match client.maintain(&lease).await {
                Outcome::Renewed(renewed) => {
                    tracing::debug!(interface = %link.name, "DHCP: lease of {} renewed", renewed.address);
                    apply_lease(&netlink, &link, Some(&lease), &renewed, metric).await;
                    shared.bind(rank, &link.name, renewed.clone());
                    lease = renewed;
                }
                Outcome::Nak(nak) => {
                    tracing::warn!(interface = %link.name, "DHCP: lease of {} revoked: {nak}", lease.address);
                    break;
                }
                Outcome::Expired => {
                    tracing::warn!(interface = %link.name, "DHCP: lease of {} expired", lease.address);
                    break;
                }
            }
        }
        remove_lease(&netlink, &link, &lease, metric).await;
        shared.unbind(rank);
    }
}

/// Acquires a lease over a packet socket, opened only for that long.
async fn acquire(client: &Client<UdpSocket>, link: &Link) -> Lease {
    loop {
        match RawSocket::open(link.index) {
            Ok(socket) => return client.acquire(&socket).await,
            Err(err) => {
                tracing::error!(interface = %link.name, "DHCP packet socket: {err}");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

/// Configures `new` on `link`, removing what `old` configured and `new` does not. Errors are
/// logged: a partially applied lease is still better than none, and it is retried on renewal.
async fn apply_lease(netlink: &Netlink, link: &Link, old: Option<&Lease>, new: &Lease, metric: u32) {
    let routes = new.routes();
    if let Some(old) = old {
        let moved = (old.address, old.prefix_len) != (new.address, new.prefix_len);
        for route in old
            .routes()
            .iter()
            .filter(|route| moved || !routes.contains(route))
            .rev()
        {
            log_error(netlink.delete_route(link, route, metric).await);
        }
        if moved {
            log_error(netlink.delete_address(link, old.address, old.prefix_len).await);
        }
    }
    if let Some(mtu) = new.mtu
        && old.is_none_or(|old| old.mtu != new.mtu)
    {
        log_error(netlink.set_mtu(link, mtu).await);
    }
    log_error(netlink.replace_address(link, new, metric).await);
    for route in &routes {
        log_error(netlink.replace_route(link, route, new.address, metric).await);
    }
}

async fn remove_lease(netlink: &Netlink, link: &Link, lease: &Lease, metric: u32) {
    for route in lease.routes().iter().rev() {
        log_error(netlink.delete_route(link, route, metric).await);
    }
    log_error(netlink.delete_address(link, lease.address, lease.prefix_len).await);
}

fn log_error(result: anyhow::Result<()>) {
    if let Err(err) = result {
        tracing::error!("{err:#}");
    }
}

/// State shared by the DHCP clients of all interfaces.
struct Shared {
    runtime_dir: PathBuf,
    next_rank: AtomicU32,
    state: Mutex<State>,
    /// Number of interfaces currently holding a lease.
    bound: watch::Sender<usize>,
}

#[derive(Default)]
struct State {
    /// Interfaces in discovery order.
    interfaces: Vec<String>,
    /// Current leases by rank (bind order): the first entry is the primary interface.
    by_rank: BTreeMap<u32, (String, Lease)>,
    /// Replaces the leased nameservers and search domains (each list when not empty).
    dns_override: DnsSettings,
}

impl State {
    fn resolver(&self) -> (Vec<IpAddr>, Vec<String>) {
        resolver_config(&self.dns_override, self.by_rank.values().map(|(_, lease)| lease))
    }
}

impl Shared {
    fn new(runtime_dir: PathBuf) -> Self {
        Self {
            runtime_dir,
            next_rank: AtomicU32::new(0),
            state: Mutex::new(State::default()),
            bound: watch::Sender::new(0),
        }
    }

    fn state_lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn add_interface(&self, name: &str) {
        self.state_lock().interfaces.push(name.to_owned());
    }

    fn next_rank(&self) -> u32 {
        self.next_rank.fetch_add(1, Ordering::Relaxed)
    }

    fn bind(&self, rank: u32, name: &str, lease: Lease) {
        self.update(|state| {
            state.by_rank.insert(rank, (name.to_owned(), lease));
        });
    }

    fn unbind(&self, rank: u32) {
        self.update(|state| {
            state.by_rank.remove(&rank);
        });
    }

    /// Applies `change` to the leases, then rewrites `resolv.conf` and notifies waiters.
    fn update(&self, change: impl FnOnce(&mut State)) {
        let count = {
            let mut state = self.state_lock();
            change(&mut state);
            if let Err(err) = self.write_resolv_conf_locked(&state) {
                tracing::error!("writing resolv.conf: {err}");
            }
            state.by_rank.len()
        };
        self.bound.send_replace(count);
    }

    fn set_dns_override(&self, dns: DnsSettings) -> io::Result<()> {
        let mut state = self.state_lock();
        state.dns_override = dns;
        self.write_resolv_conf_locked(&state)
    }

    fn write_resolv_conf(&self) -> io::Result<()> {
        self.write_resolv_conf_locked(&self.state_lock())
    }

    /// Called with the state lock held, so that concurrent updates are written in order.
    fn write_resolv_conf_locked(&self, state: &State) -> io::Result<()> {
        let (nameservers, search) = state.resolver();
        dns::write_atomic(
            &self.runtime_dir,
            "resolv.conf",
            &dns::render_resolv_conf(&nameservers, &search),
        )
    }

    fn snapshot(&self) -> NetworkState {
        let state = self.state_lock();
        let leased = state.by_rank.values().map(|(name, lease)| InterfaceState {
            name: name.clone(),
            lease: Some(LeaseInfo {
                address: lease.address,
                prefix_len: lease.prefix_len,
                gateway: lease
                    .routes()
                    .iter()
                    .find(|r| r.prefix_len == 0)
                    .and_then(|r| r.gateway),
                mtu: lease.mtu,
            }),
        });
        let unleased = state
            .interfaces
            .iter()
            .filter(|name| !state.by_rank.values().any(|(leased, _)| leased == *name))
            .map(|name| InterfaceState {
                name: name.clone(),
                lease: None,
            });
        NetworkState {
            interfaces: leased.chain(unleased).collect(),
            nameservers: state.resolver().0,
            dhcp_hostname: state
                .by_rank
                .values()
                .next()
                .and_then(|(_, lease)| lease.hostname.clone()),
        }
    }
}

/// Nameservers and search domains from `leases` (primary first); each configured list replaces
/// the leased one.
fn resolver_config<'a>(
    configured: &DnsSettings,
    leases: impl Iterator<Item = &'a Lease> + Clone,
) -> (Vec<IpAddr>, Vec<String>) {
    let nameservers = if configured.name_servers.is_empty() {
        leases
            .clone()
            .flat_map(|lease| lease.nameservers.iter().copied().map(IpAddr::V4))
            .collect()
    } else {
        configured.name_servers.clone()
    };
    let search = if configured.search_list.is_empty() {
        leases
            .flat_map(|lease| {
                if lease.search.is_empty() {
                    lease.domain_name.as_slice()
                } else {
                    lease.search.as_slice()
                }
            })
            .cloned()
            .collect()
    } else {
        configured.search_list.iter().map(|domain| domain.to_string()).collect()
    };
    (nameservers, search)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(nameservers: &[[u8; 4]], domain: Option<&str>, search: &[&str]) -> Lease {
        Lease {
            address: Ipv4Addr::new(10, 0, 0, 5),
            prefix_len: 24,
            server: Ipv4Addr::new(10, 0, 0, 1),
            routers: vec![Ipv4Addr::new(10, 0, 0, 1)],
            classless_routes: Vec::new(),
            nameservers: nameservers.iter().copied().map(Ipv4Addr::from).collect(),
            domain_name: domain.map(String::from),
            search: search.iter().copied().map(String::from).collect(),
            hostname: Some("web-1".parse().unwrap()),
            mtu: Some(1460),
            timers: None,
            start: Instant::now(),
        }
    }

    #[test]
    fn resolver_config_merges_leases() {
        let primary = lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]);
        let secondary = lease(
            &[[10, 1, 0, 2]],
            Some("ignored.internal"),
            &["b.internal", "c.internal"],
        );
        let (servers, search) = resolver_config(&DnsSettings::default(), [&primary, &secondary].into_iter());
        assert_eq!(
            servers,
            ["10.0.0.2".parse::<IpAddr>().unwrap(), "10.1.0.2".parse().unwrap()]
        );
        assert_eq!(search, ["a.internal", "b.internal", "c.internal"]);

        let configured = DnsSettings {
            name_servers: vec!["1.1.1.1".parse().unwrap()],
            ..DnsSettings::default()
        };
        let (servers, search) = resolver_config(&configured, [&primary].into_iter());
        assert_eq!(servers, configured.name_servers);
        assert_eq!(search, ["a.internal"], "search domains still come from DHCP");

        let configured = DnsSettings {
            search_list: vec!["corp.example".parse().unwrap()],
            ..DnsSettings::default()
        };
        let (servers, search) = resolver_config(&configured, [&primary].into_iter());
        assert_eq!(
            servers,
            ["10.0.0.2".parse::<IpAddr>().unwrap()],
            "nameservers still come from DHCP"
        );
        assert_eq!(search, ["corp.example"]);
    }

    #[test]
    fn state_lists_primary_first() {
        let dir = tempfile::tempdir().unwrap();
        let shared = Shared::new(dir.path().into());
        for name in ["eth0", "eth1", "eth2"] {
            shared.add_interface(name);
        }
        shared.bind(0, "eth1", lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]));
        shared.bind(
            1,
            "eth0",
            Lease {
                hostname: None,
                ..lease(&[[10, 1, 0, 2]], None, &[])
            },
        );
        let state = shared.snapshot();
        let names: Vec<_> = state.interfaces.iter().map(|i| i.name.as_str()).collect();
        assert_eq!(names, ["eth1", "eth0", "eth2"]);
        assert_eq!(
            state.interfaces[0].lease.as_ref().unwrap().gateway,
            Some(Ipv4Addr::new(10, 0, 0, 1))
        );
        assert_eq!(state.interfaces[2].lease, None);
        assert_eq!(state.dhcp_hostname.as_ref().map(Hostname::as_str), Some("web-1"));
        assert_eq!(
            std::fs::read_to_string(dir.path().join("resolv.conf")).unwrap(),
            "# Generated by dust-init.\nnameserver 10.0.0.2\nnameserver 10.1.0.2\nsearch a.internal\n"
        );
        assert_eq!(*shared.bound.borrow(), 2);

        shared.unbind(0);
        assert_eq!(shared.snapshot().interfaces[0].name, "eth0");
        assert_eq!(*shared.bound.borrow(), 1);
    }

    #[test]
    fn dns_override_survives_lease_updates() {
        let dir = tempfile::tempdir().unwrap();
        let resolv_conf = || std::fs::read_to_string(dir.path().join("resolv.conf")).unwrap();
        let shared = Shared::new(dir.path().into());
        shared.bind(0, "eth0", lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]));

        shared
            .set_dns_override(DnsSettings {
                name_servers: vec!["192.0.2.53".parse().unwrap()],
                search_list: vec!["corp.example".parse().unwrap()],
            })
            .unwrap();
        let overridden = "# Generated by dust-init.\nnameserver 192.0.2.53\nsearch corp.example\n";
        assert_eq!(resolv_conf(), overridden);
        shared.bind(0, "eth0", lease(&[[10, 0, 0, 3]], Some("a.internal"), &[]));
        assert_eq!(resolv_conf(), overridden, "a renewal keeps the override");
        assert_eq!(shared.snapshot().nameservers, ["192.0.2.53".parse::<IpAddr>().unwrap()]);

        shared.set_dns_override(DnsSettings::default()).unwrap();
        assert_eq!(
            resolv_conf(),
            "# Generated by dust-init.\nnameserver 10.0.0.3\nsearch a.internal\n",
            "back to DHCP"
        );
    }

    #[test]
    fn writes_hosts() {
        let dir = tempfile::tempdir().unwrap();
        write_hosts_in(dir.path(), &"node.example.com".parse().unwrap()).unwrap();
        let hosts = std::fs::read_to_string(dir.path().join("hosts")).unwrap();
        assert!(hosts.contains("127.0.1.1\tnode.example.com node\n"));
    }

    /// End-to-end test against DHCP servers on veth peers. The client side runs in a user +
    /// network namespace (`unshare -rn`); the servers run in a nested network namespace of their
    /// own, as a server sharing the client's namespace would see its own address as the source of
    /// the client's packets (Linux picks any local address when the interface has none).
    mod netns {
        use std::process::{Child, Command};

        use dhcproto::Decodable;
        use dhcproto::v4::{DhcpOption, Message, MessageType};
        use futures::TryStreamExt as _;
        use rtnetlink::packet_route::address::AddressAttribute;
        use rtnetlink::packet_route::link::LinkAttribute;
        use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute, RouteProtocol, RouteScope};
        use rtnetlink::{Handle, LinkUnspec, LinkVeth, RouteMessageBuilder};

        use super::super::dhcp::tests::reply_to;
        use super::super::dhcp::{CLIENT_PORT, SERVER_PORT, bind_port};
        use super::*;

        const TEST: &str = "net::tests::netns::dhcp_end_to_end";
        const SERVER0: Ipv4Addr = Ipv4Addr::new(10, 42, 0, 1);
        const SERVER1: Ipv4Addr = Ipv4Addr::new(10, 43, 0, 1);
        /// Role of the test process: unset (launcher), `client` or `server`.
        const ROLE: &str = "DUST_NET_TEST_ROLE";

        #[test]
        #[ignore = "needs unprivileged user namespaces (unshare -rn)"]
        fn dhcp_end_to_end() {
            let runtime = || tokio::runtime::Runtime::new().unwrap();
            match std::env::var(ROLE).as_deref() {
                Ok("client") => runtime().block_on(client()),
                Ok("server") => runtime().block_on(servers()),
                _ => {
                    let status = rerun(&["--user", "--map-root-user", "--net"], "client")
                        .status()
                        .unwrap();
                    assert!(status.success(), "test inside the namespace failed: {status}");
                }
            }
        }

        /// This test, run again in new namespaces by `unshare`.
        fn rerun(namespaces: &[&str], role: &str) -> Command {
            let mut command = Command::new("unshare");
            command
                .args(namespaces)
                .arg("--")
                .arg(std::env::current_exe().unwrap())
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

        async fn link(handle: &Handle, name: &str) -> Option<rtnetlink::packet_route::link::LinkMessage> {
            handle
                .link()
                .get()
                .match_name(name)
                .execute()
                .try_next()
                .await
                .ok()
                .flatten()
        }

        async fn index(handle: &Handle, name: &str) -> u32 {
            link(handle, name).await.unwrap().header.index
        }

        /// The server process: configures the server ends of the veth pairs once they are moved
        /// into its namespace, then serves forever.
        async fn servers() {
            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            tokio::spawn(connection);
            for (name, address) in [("srv0", SERVER0), ("srv1", SERVER1)] {
                while link(&handle, name).await.is_none() {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                }
                handle
                    .link()
                    .set(LinkUnspec::new_with_name(name).up().build())
                    .execute()
                    .await
                    .unwrap();
                let index = index(&handle, name).await;
                handle.address().add(index, address.into(), 24).execute().await.unwrap();
            }
            // A plain /24 with a short lease, renewed during the test.
            let short = tokio::spawn(serve(
                "srv0",
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

        /// A minimal server for one client on `ifname`, handing out `address`.
        async fn serve(ifname: &str, address: Ipv4Addr, options: Vec<DhcpOption>) {
            let socket = bind_port(ifname, SERVER_PORT).unwrap();
            let mut buf = vec![0u8; 1500];
            loop {
                let (len, _) = socket.recv_from(&mut buf).await.unwrap();
                let Ok(request) = Message::from_bytes(&buf[..len]) else {
                    continue;
                };
                let (kind, target) = match request.opts().msg_type() {
                    Some(MessageType::Discover) => (MessageType::Offer, Ipv4Addr::BROADCAST),
                    Some(MessageType::Request) if request.ciaddr().is_unspecified() => {
                        (MessageType::Ack, Ipv4Addr::BROADCAST)
                    }
                    Some(MessageType::Request) => (MessageType::Ack, request.ciaddr()),
                    _ => continue,
                };
                let reply = reply_to(&request, kind, address, options.clone());
                socket.send_to(&reply, (target, CLIENT_PORT)).await.unwrap();
            }
        }

        /// DHCP routes of `ifname`, formatted like `ip route`.
        async fn routes(handle: &Handle, ifname: &str) -> Vec<String> {
            let index = index(handle, ifname).await;
            let request = handle.route().get(RouteMessageBuilder::<Ipv4Addr>::new().build());
            let dump: Vec<_> = request.execute().try_collect().await.unwrap();
            dump.into_iter()
                .filter(|msg| msg.header.protocol == RouteProtocol::Dhcp)
                .filter(|msg| msg.attributes.contains(&RouteAttribute::Oif(index)))
                .map(|msg| {
                    let mut line = match msg.attributes.iter().find_map(|attr| match attr {
                        RouteAttribute::Destination(RouteAddress::Inet(dst)) => Some(dst),
                        _ => None,
                    }) {
                        Some(dst) => format!("{dst}/{}", msg.header.destination_prefix_length),
                        None => "default".to_owned(),
                    };
                    for attr in &msg.attributes {
                        if let RouteAttribute::Gateway(RouteAddress::Inet(gw)) = attr {
                            line.push_str(&format!(" via {gw}"));
                        }
                    }
                    for attr in &msg.attributes {
                        if let RouteAttribute::Priority(metric) = attr {
                            line.push_str(&format!(" metric {metric}"));
                        }
                    }
                    if msg.header.scope == RouteScope::Link {
                        line.push_str(" scope link");
                    }
                    line
                })
                .collect()
        }

        async fn addresses(handle: &Handle, ifname: &str) -> Vec<String> {
            let index = index(handle, ifname).await;
            let request = handle.address().get().set_link_index_filter(index);
            let dump: Vec<_> = request.execute().try_collect().await.unwrap();
            dump.into_iter()
                .filter_map(|msg| {
                    msg.attributes.iter().find_map(|attr| match attr {
                        AddressAttribute::Address(IpAddr::V4(addr)) => {
                            Some(format!("{addr}/{}", msg.header.prefix_len))
                        }
                        _ => None,
                    })
                })
                .collect()
        }

        async fn mtu(handle: &Handle, ifname: &str) -> u32 {
            let msg = link(handle, ifname).await.unwrap();
            msg.attributes
                .iter()
                .find_map(|a| match a {
                    LinkAttribute::Mtu(mtu) => Some(*mtu),
                    _ => None,
                })
                .unwrap()
        }

        async fn client() {
            let _ = tracing_subscriber::fmt()
                .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "dust_init=debug".into()))
                .with_test_writer()
                .try_init();
            // Strict reverse path filtering, as dust-init's sysctl defaults: replies arriving before
            // the interface has an address are dropped by the kernel, packet sockets see them.
            for conf in ["all", "default"] {
                std::fs::write(format!("/proc/sys/net/ipv4/conf/{conf}/rp_filter"), "1").unwrap();
            }

            let (connection, handle, _) = rtnetlink::new_connection().unwrap();
            tokio::spawn(connection);

            let servers = Servers(rerun(&["--net"], "server").spawn().unwrap());
            let own_netns = std::fs::read_link("/proc/self/ns/net").unwrap();
            let server_netns = format!("/proc/{}/ns/net", servers.0.id());
            while std::fs::read_link(&server_netns).is_ok_and(|ns| ns == own_netns) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            for (client, server) in [("dhcp0", "srv0"), ("dhcp1", "srv1")] {
                handle
                    .link()
                    .add(LinkVeth::new(client, server).build())
                    .execute()
                    .await
                    .unwrap();
                let moved = LinkUnspec::new_with_name(server).setns_by_pid(servers.0.id()).build();
                handle.link().set(moved).execute().await.unwrap();
            }

            let runtime_dir = tempfile::tempdir().unwrap();
            let options = Options {
                runtime_dir: runtime_dir.path().into(),
                interfaces: Interfaces::Fixed(vec!["dhcp0".into(), "dhcp1".into()]),
                link_timeout: Duration::from_secs(1),
                lease_timeout: Duration::from_secs(20),
            };
            let (state, shared) = configure_with(options).await.unwrap();
            assert!(state.interfaces[0].lease.is_some(), "no lease: {state:?}");
            let bound = Instant::now();

            // Wait for both leases.
            let mut leases = shared.bound.subscribe();
            let both = leases.wait_for(|&count| count == 2);
            tokio::time::timeout(Duration::from_secs(20), both)
                .await
                .expect("second lease missing")
                .unwrap();

            // The primary interface has the lowest metric.
            let metrics = |name: &str| if state.interfaces[0].name == name { 1024 } else { 1124 };
            assert_eq!(addresses(&handle, "dhcp0").await, ["10.42.0.10/24"]);
            assert_eq!(mtu(&handle, "dhcp0").await, 1400);
            assert_eq!(
                routes(&handle, "dhcp0").await,
                [format!("default via 10.42.0.1 metric {}", metrics("dhcp0"))]
            );
            assert_eq!(addresses(&handle, "dhcp1").await, ["10.43.0.10/32"]);
            let metric = metrics("dhcp1");
            let mut gcp_routes = routes(&handle, "dhcp1").await;
            gcp_routes.sort();
            assert_eq!(
                gcp_routes,
                [
                    format!("10.43.0.1/32 metric {metric} scope link"),
                    format!("default via 10.43.0.1 metric {metric}"),
                ]
            );
            let resolv_conf = || std::fs::read_to_string(runtime_dir.path().join("resolv.conf")).unwrap();
            let resolv = resolv_conf();
            assert!(resolv.contains("nameserver 10.42.0.53\n"), "{resolv}");
            assert!(resolv.contains("nameserver 10.43.0.53\n"), "{resolv}");
            assert!(resolv.contains("search test.internal\n"), "{resolv}");

            shared
                .set_dns_override(DnsSettings {
                    name_servers: vec!["192.0.2.53".parse().unwrap()],
                    ..DnsSettings::default()
                })
                .unwrap();
            let overridden = "# Generated by dust-init.\nnameserver 192.0.2.53\nsearch test.internal\n";
            assert_eq!(resolv_conf(), overridden);

            // The 4 s lease of dhcp0 outlives its expiry only if it is renewed.
            tokio::time::sleep_until(bound + Duration::from_secs(9)).await;
            assert_eq!(
                addresses(&handle, "dhcp0").await,
                ["10.42.0.10/24"],
                "lease not renewed"
            );
            assert_eq!(routes(&handle, "dhcp0").await.len(), 1);
            assert_eq!(resolv_conf(), overridden, "renewals keep the override");
        }
    }
}

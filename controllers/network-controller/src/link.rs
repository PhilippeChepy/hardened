//! Interface discovery (sysfs) and configuration (rtnetlink).

use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use netlink_packet_core::NLM_F_CREATE;
use netlink_packet_core::NLM_F_DUMP;
use netlink_packet_core::NLM_F_REPLACE;
use netlink_packet_route::AddressFamily;
use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::address::AddressAttribute;
use netlink_packet_route::address::AddressMessage;
use netlink_packet_route::address::CacheInfo;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::link::LinkMessage;
use netlink_packet_route::route::RouteAddress;
use netlink_packet_route::route::RouteAttribute;
use netlink_packet_route::route::RouteHeader;
use netlink_packet_route::route::RouteMessage;
use netlink_packet_route::route::RouteProtocol;
use netlink_packet_route::route::RouteScope;
use netlink_packet_route::route::RouteType;
use rustix::io::Errno;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::dhcp::Lease;
use crate::dhcp::Route;
use crate::link_events::LinkEvent;
use crate::link_events::LinkEvents;
use crate::link_events::LinkState;
use crate::netlink_socket::NetlinkSocket;
use crate::prefix_len::PrefixLen;

/// `ARPHRD_ETHER`.
const ARPHRD_ETHER: u32 = 1;

/// Whether the interface `name` of `sysfs_net` (`/sys/class/net`) is a physical Ethernet one:
/// backed by a device (virtual ones live under `/sys/devices/virtual`), of type `ARPHRD_ETHER`
/// and not wireless.
#[must_use]
pub fn is_physical_ethernet(sysfs_net: &Path, name: &str) -> bool {
    // The kernel's names are path components already; checked all the same.
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return false;
    }
    let dir = sysfs_net.join(name);
    let is_ether = fs::read_to_string(dir.join("type"))
        .is_ok_and(|t| t.trim().parse::<u32>().is_ok_and(|t| t == ARPHRD_ETHER));
    let physical = dir.join("device").exists();
    let wireless = dir.join("wireless").exists() || dir.join("phy80211").exists();
    is_ether && physical && !wireless
}

/// An interface, as needed to run DHCP on it.
pub struct Link {
    /// Its kernel name, e.g. `eth0`.
    pub name: String,
    /// Its interface index.
    pub index: u32,
    /// Its Ethernet address.
    pub mac: [u8; 6],
}

/// rtnetlink operations on links, addresses and routes, over one socket shared by the
/// interfaces' tasks: a request and its replies hold it.
#[derive(Clone)]
pub struct Netlink {
    socket: Arc<Mutex<NetlinkSocket>>,
}

impl Netlink {
    /// Opens a route netlink socket.
    ///
    /// # Panics
    ///
    /// Outside of a tokio runtime.
    pub fn connect() -> io::Result<Self> {
        Ok(Self {
            socket: Arc::new(Mutex::new(NetlinkSocket::open(0)?)),
        })
    }

    /// Sends `message` with `flags` and returns the replies (see [`NetlinkSocket::request`]).
    pub async fn request(
        &self,
        message: RouteNetlinkMessage,
        flags: u16,
    ) -> io::Result<Vec<RouteNetlinkMessage>> {
        self.socket.lock().await.request(message, flags).await
    }

    /// The kernel's description of the interface `name`.
    pub async fn link_message(&self, name: &str) -> anyhow::Result<LinkMessage> {
        let mut msg = LinkMessage::default();
        msg.attributes.push(LinkAttribute::IfName(name.to_owned()));
        self.request(RouteNetlinkMessage::GetLink(msg), 0)
            .await
            .with_context(|| format!("looking up interface {name}"))?
            .into_iter()
            .find_map(|reply| match reply {
                RouteNetlinkMessage::NewLink(msg) => Some(msg),
                _ => None,
            })
            .with_context(|| format!("no interface {name}"))
    }

    /// Every link.
    pub async fn links(&self) -> io::Result<Vec<LinkState>> {
        let request = RouteNetlinkMessage::GetLink(LinkMessage::default());
        Ok(self
            .request(request, NLM_F_DUMP)
            .await?
            .iter()
            .filter_map(|reply| match reply {
                RouteNetlinkMessage::NewLink(msg) => LinkState::from_message(msg),
                _ => None,
            })
            .collect())
    }

    /// Brings the interface `name` up.
    pub async fn set_up(&self, name: &str) -> anyhow::Result<()> {
        let mut msg = LinkMessage::default();
        msg.header.flags = LinkFlags::Up;
        msg.header.change_mask = LinkFlags::Up;
        msg.attributes.push(LinkAttribute::IfName(name.to_owned()));
        self.request(RouteNetlinkMessage::SetLink(msg), 0)
            .await
            .with_context(|| format!("bringing {name} up"))?;
        Ok(())
    }

    /// Waits up to `timeout` for the carrier (`IFF_LOWER_UP`) of `link`; returns whether it came
    /// up.
    #[must_use]
    pub async fn wait_for_carrier(&self, link: &Link, timeout: Duration) -> bool {
        let mut events = match LinkEvents::subscribe() {
            Ok(events) => events,
            Err(err) => {
                tracing::warn!(interface = %link.name, "subscribing to link events: {err}");
                return false;
            }
        };
        let carrier = async {
            // Whether to look the link up: once subscribed, then after lost notifications.
            let mut look_up = true;
            loop {
                if look_up {
                    match self.link_message(&link.name).await {
                        Ok(msg) if msg.header.flags.contains(LinkFlags::LowerUp) => return true,
                        Ok(_) => {}
                        Err(err) => tracing::debug!("{err:#}"),
                    }
                }
                look_up = match events.next().await {
                    Ok(LinkEvent::Changed(state)) if state.index == link.index => {
                        if state.lower_up {
                            return true;
                        }
                        false
                    }
                    Ok(LinkEvent::Removed(state)) if state.index == link.index => return false,
                    Ok(LinkEvent::Lost) => true,
                    Ok(_) => false,
                    Err(err) => {
                        tracing::warn!(interface = %link.name, "link events: {err}");
                        return false;
                    }
                };
            }
        };
        tokio::time::timeout(timeout, carrier)
            .await
            .unwrap_or(false)
    }

    /// Sets the MTU of `link`.
    pub async fn set_mtu(&self, link: &Link, mtu: u16) -> anyhow::Result<()> {
        let mut msg = LinkMessage::default();
        msg.header.index = link.index;
        msg.attributes.push(LinkAttribute::Mtu(mtu.into()));
        self.request(RouteNetlinkMessage::SetLink(msg), 0)
            .await
            .with_context(|| format!("setting MTU {mtu} on {}", link.name))?;
        Ok(())
    }

    /// Adds or refreshes the leased address, with the lease's lifetime so that the kernel drops
    /// it if network-controller stops renewing, and `metric` on its prefix route.
    pub async fn replace_address(
        &self,
        link: &Link,
        lease: &Lease,
        metric: u32,
    ) -> anyhow::Result<()> {
        let mut msg = address_message(link.index, lease.address, lease.prefix_len);
        let lifetime = lease.remaining_secs(Instant::now());
        let mut cache_info = CacheInfo::default();
        cache_info.ifa_valid = lifetime;
        cache_info.ifa_preferred = lifetime;
        msg.attributes.push(AddressAttribute::CacheInfo(cache_info));
        msg.attributes.push(AddressAttribute::RoutePriority(metric));
        self.request(
            RouteNetlinkMessage::NewAddress(msg),
            NLM_F_CREATE | NLM_F_REPLACE,
        )
        .await
        .with_context(|| {
            format!(
                "adding {}/{} to {}",
                lease.address, lease.prefix_len, link.name
            )
        })?;
        Ok(())
    }

    /// Removes an address from `link`, if it has it.
    pub async fn delete_address(
        &self,
        link: &Link,
        address: Ipv4Addr,
        prefix_len: PrefixLen,
    ) -> anyhow::Result<()> {
        let msg = address_message(link.index, address, prefix_len);
        ignore_missing(self.request(RouteNetlinkMessage::DelAddress(msg), 0).await)
            .with_context(|| format!("removing {address}/{prefix_len} from {}", link.name))
    }

    /// Adds or replaces `route` through `link`, from `source`.
    pub async fn replace_route(
        &self,
        link: &Link,
        route: &Route,
        source: Ipv4Addr,
        metric: u32,
    ) -> anyhow::Result<()> {
        let msg = route_message(link.index, route, Some(source), metric);
        self.request(
            RouteNetlinkMessage::NewRoute(msg),
            NLM_F_CREATE | NLM_F_REPLACE,
        )
        .await
        .with_context(|| format!("adding route {route} on {}", link.name))?;
        Ok(())
    }

    /// Removes `route` through `link`, if present.
    pub async fn delete_route(
        &self,
        link: &Link,
        route: &Route,
        metric: u32,
    ) -> anyhow::Result<()> {
        let msg = route_message(link.index, route, None, metric);
        ignore_missing(self.request(RouteNetlinkMessage::DelRoute(msg), 0).await)
            .with_context(|| format!("removing route {route} from {}", link.name))
    }
}

/// The address `address/prefix_len` of interface `index`, with its broadcast address below /31.
#[must_use]
pub fn address_message(index: u32, address: Ipv4Addr, prefix_len: PrefixLen) -> AddressMessage {
    let mut msg = AddressMessage::default();
    msg.header.family = AddressFamily::Inet;
    msg.header.prefix_len = prefix_len.get();
    msg.header.index = index;
    msg.attributes
        .push(AddressAttribute::Address(address.into()));
    msg.attributes.push(AddressAttribute::Local(address.into()));
    if prefix_len.get() < 31 {
        let broadcast = Ipv4Addr::from(u32::from(address) | !prefix_len.mask());
        msg.attributes.push(AddressAttribute::Broadcast(broadcast));
    }
    msg
}

/// The kernel route for `route` through interface `index`.
#[must_use]
fn route_message(index: u32, route: &Route, source: Option<Ipv4Addr>, metric: u32) -> RouteMessage {
    let mut msg = RouteMessage::default();
    msg.header.address_family = AddressFamily::Inet;
    msg.header.table = RouteHeader::RT_TABLE_MAIN;
    msg.header.protocol = RouteProtocol::Dhcp;
    msg.header.kind = RouteType::Unicast;
    msg.header.destination_prefix_length = route.prefix_len.get();
    msg.header.scope = match route.gateway {
        Some(_) => RouteScope::Universe,
        None => RouteScope::Link,
    };
    let attributes = &mut msg.attributes;
    attributes.push(RouteAttribute::Destination(RouteAddress::Inet(
        route.destination,
    )));
    attributes.push(RouteAttribute::Oif(index));
    attributes.push(RouteAttribute::Priority(metric));
    if let Some(gateway) = route.gateway {
        attributes.push(RouteAttribute::Gateway(RouteAddress::Inet(gateway)));
    }
    if let Some(source) = source {
        attributes.push(RouteAttribute::PrefSource(RouteAddress::Inet(source)));
    }
    msg
}

/// Treats "no such address/route" as success, for idempotent removals.
fn ignore_missing(result: io::Result<Vec<RouteNetlinkMessage>>) -> io::Result<()> {
    match result {
        Err(err)
            if [Errno::SRCH, Errno::ADDRNOTAVAIL, Errno::NOENT]
                .iter()
                .any(|errno| err.raw_os_error() == Some(errno.raw_os_error())) =>
        {
            Ok(())
        }
        other => other.map(drop),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix;

    use super::*;

    #[test]
    fn discovers_physical_ethernet() {
        let sys = tempfile::tempdir().unwrap();
        let device = sys.path().join("devices/pci0000:00/0000:00:03.0");
        fs::create_dir_all(&device).unwrap();
        let net = sys.path().join("class/net");
        let add = |name: &str, kind: u32, physical: bool| {
            let dir = net.join(name);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("type"), format!("{kind}\n")).unwrap();
            if physical {
                unix::fs::symlink(&device, dir.join("device")).unwrap();
            }
            dir
        };
        add("ens4", 1, /* physical */ true);
        add("eth0", 1, /* physical */ true);
        add("ib0", 32, /* physical */ true);
        add("lo", 772, /* physical */ false);
        add("docker0", 1, /* physical */ false);
        fs::create_dir(add("wlan0", 1, /* physical */ true).join("phy80211")).unwrap();
        for (name, expected) in [
            ("ens4", true),
            ("eth0", true),
            ("ib0", false),
            ("lo", false),
            ("docker0", false),
            ("wlan0", false),
            ("missing", false),
            ("..", false),
            ("", false),
        ] {
            assert_eq!(is_physical_ethernet(&net, name), expected, "{name:?}");
        }
    }

    #[test]
    fn builds_route_messages() {
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        let default = Route {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: PrefixLen::ZERO,
            gateway: Some(gateway),
        };
        let msg = route_message(3, &default, Some(Ipv4Addr::new(10, 0, 0, 5)), 1024);
        assert_eq!(msg.header.destination_prefix_length, 0);
        assert_eq!(msg.header.scope, RouteScope::Universe);
        assert_eq!(msg.header.protocol, RouteProtocol::Dhcp);
        assert!(
            msg.attributes
                .contains(&RouteAttribute::Gateway(RouteAddress::Inet(gateway)))
        );
        assert!(msg.attributes.contains(&RouteAttribute::Oif(3)));
        assert!(msg.attributes.contains(&RouteAttribute::Priority(1024)));

        let on_link = Route {
            destination: gateway,
            prefix_len: PrefixLen::HOST,
            gateway: None,
        };
        let msg = route_message(3, &on_link, None, 1024);
        assert_eq!(msg.header.scope, RouteScope::Link);
        assert_eq!(msg.header.destination_prefix_length, 32);
        assert_eq!(msg.header.table, RouteHeader::RT_TABLE_MAIN);
        assert!(
            msg.attributes
                .contains(&RouteAttribute::Destination(RouteAddress::Inet(gateway)))
        );
        assert!(
            !msg.attributes
                .iter()
                .any(|a| matches!(a, RouteAttribute::Gateway(_)))
        );
    }

    #[test]
    fn builds_address_messages() {
        let address = Ipv4Addr::new(10, 0, 0, 5);
        let msg = address_message(3, address, PrefixLen::new(24).unwrap());
        assert_eq!(msg.header.index, 3);
        assert_eq!(msg.header.prefix_len, 24);
        assert_eq!(
            msg.attributes,
            [
                AddressAttribute::Address(address.into()),
                AddressAttribute::Local(address.into()),
                AddressAttribute::Broadcast(Ipv4Addr::new(10, 0, 0, 255)),
            ]
        );
        let msg = address_message(3, address, PrefixLen::HOST);
        assert_eq!(msg.attributes.len(), 2, "no broadcast address on a /32");
    }

    /// Against the kernel, in the test's network namespace.
    #[tokio::test]
    async fn dumps_links_and_maps_errors() {
        let netlink = Netlink::connect().unwrap();
        let links = netlink.links().await.unwrap();
        let lo = links.iter().find(|link| link.name == "lo").expect("no lo");
        let msg = netlink.link_message("lo").await.unwrap();
        assert_eq!(msg.header.index, lo.index);

        let missing = RouteNetlinkMessage::GetLink({
            let mut msg = LinkMessage::default();
            msg.attributes
                .push(LinkAttribute::IfName("missing0".into()));
            msg
        });
        let err = netlink.request(missing, 0).await.unwrap_err();
        assert_eq!(err.raw_os_error(), Some(Errno::NODEV.raw_os_error()));
        // The socket stays usable after an error.
        assert_eq!(netlink.links().await.unwrap(), links);
    }
}

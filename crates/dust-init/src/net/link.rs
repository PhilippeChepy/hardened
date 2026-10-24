//! Interface discovery (sysfs) and configuration (rtnetlink).

use std::fs;
use std::io;
use std::net::Ipv4Addr;
use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use futures::TryStreamExt as _;
use rtnetlink::packet_route::address::{AddressAttribute, CacheInfo};
use rtnetlink::packet_route::link::{LinkAttribute, LinkFlags, LinkMessage};
use rtnetlink::packet_route::route::{RouteMessage, RouteProtocol, RouteScope};
use rtnetlink::{AddressMessageBuilder, Handle, LinkUnspec, RouteMessageBuilder};
use rustix::io::Errno;
use tokio::time::Instant;

use super::dhcp::{Lease, Route};

/// `ARPHRD_ETHER`.
const ARPHRD_ETHER: u32 = 1;

/// Names of the physical Ethernet interfaces in `sysfs_net` (`/sys/class/net`), sorted: those
/// backed by a device (virtual ones live under `/sys/devices/virtual`), of type `ARPHRD_ETHER`
/// and not wireless.
pub fn physical_ethernet(sysfs_net: &Path) -> io::Result<Vec<String>> {
    let mut names = Vec::new();
    for entry in fs::read_dir(sysfs_net)? {
        let entry = entry?;
        let dir = entry.path();
        let is_ether = fs::read_to_string(dir.join("type"))
            .is_ok_and(|t| t.trim().parse::<u32>().is_ok_and(|t| t == ARPHRD_ETHER));
        let physical = dir.join("device").exists();
        let wireless = dir.join("wireless").exists() || dir.join("phy80211").exists();
        if is_ether
            && physical
            && !wireless
            && let Some(name) = entry.file_name().to_str()
        {
            names.push(name.to_owned());
        }
    }
    names.sort();
    Ok(names)
}

/// An interface, as needed to run DHCP on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Link {
    pub name: String,
    pub index: u32,
    pub mac: [u8; 6],
}

/// rtnetlink operations on links, addresses and routes.
#[derive(Clone)]
pub struct Netlink {
    handle: Handle,
}

impl Netlink {
    /// Opens a route netlink socket; must be called within the tokio runtime.
    pub fn connect() -> io::Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    async fn link_message(&self, name: &str) -> anyhow::Result<LinkMessage> {
        self.handle
            .link()
            .get()
            .match_name(name.to_owned())
            .execute()
            .try_next()
            .await?
            .with_context(|| format!("no interface {name}"))
    }

    pub async fn link(&self, name: &str) -> anyhow::Result<Link> {
        let msg = self.link_message(name).await?;
        let mac = msg
            .attributes
            .iter()
            .find_map(|attr| match attr {
                LinkAttribute::Address(mac) => <[u8; 6]>::try_from(mac.as_slice()).ok(),
                _ => None,
            })
            .with_context(|| format!("{name} has no Ethernet address"))?;
        Ok(Link {
            name: name.to_owned(),
            index: msg.header.index,
            mac,
        })
    }

    pub async fn set_up(&self, name: &str) -> anyhow::Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_name(name).up().build())
            .execute()
            .await
            .with_context(|| format!("bringing {name} up"))
    }

    /// Waits up to `timeout` for the carrier (`IFF_LOWER_UP`); returns whether it came up.
    pub async fn wait_for_carrier(&self, name: &str, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            match self.link_message(name).await {
                Ok(msg) if msg.header.flags.contains(LinkFlags::LowerUp) => return true,
                Ok(_) => {}
                Err(err) => tracing::debug!("{err:#}"),
            }
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    pub async fn set_mtu(&self, link: &Link, mtu: u16) -> anyhow::Result<()> {
        self.handle
            .link()
            .set(LinkUnspec::new_with_index(link.index).mtu(mtu.into()).build())
            .execute()
            .await
            .with_context(|| format!("setting MTU {mtu} on {}", link.name))
    }

    /// Adds or refreshes the leased address, with the lease's lifetime so that the kernel drops it
    /// if dust-init stops renewing, and `metric` on its prefix route.
    pub async fn replace_address(&self, link: &Link, lease: &Lease, metric: u32) -> anyhow::Result<()> {
        let mut request = self
            .handle
            .address()
            .add(link.index, lease.address.into(), lease.prefix_len)
            .replace();
        let lifetime = lease.remaining_secs(Instant::now());
        let mut cache_info = CacheInfo::default();
        cache_info.ifa_valid = lifetime;
        cache_info.ifa_preferred = lifetime;
        let attributes = &mut request.message_mut().attributes;
        attributes.push(AddressAttribute::CacheInfo(cache_info));
        attributes.push(AddressAttribute::RoutePriority(metric));
        request
            .execute()
            .await
            .with_context(|| format!("adding {}/{} to {}", lease.address, lease.prefix_len, link.name))
    }

    pub async fn delete_address(&self, link: &Link, address: Ipv4Addr, prefix_len: u8) -> anyhow::Result<()> {
        let msg = AddressMessageBuilder::<Ipv4Addr>::new()
            .index(link.index)
            .address(address, prefix_len)
            .build();
        ignore_missing(self.handle.address().del(msg).execute().await)
            .with_context(|| format!("removing {address}/{prefix_len} from {}", link.name))
    }

    pub async fn replace_route(&self, link: &Link, route: &Route, source: Ipv4Addr, metric: u32) -> anyhow::Result<()> {
        self.handle
            .route()
            .add(route_message(link.index, route, Some(source), metric))
            .replace()
            .execute()
            .await
            .with_context(|| format!("adding route {route} on {}", link.name))
    }

    pub async fn delete_route(&self, link: &Link, route: &Route, metric: u32) -> anyhow::Result<()> {
        ignore_missing(
            self.handle
                .route()
                .del(route_message(link.index, route, None, metric))
                .execute()
                .await,
        )
        .with_context(|| format!("removing route {route} from {}", link.name))
    }
}

/// The kernel route for `route` through interface `index`.
pub fn route_message(index: u32, route: &Route, source: Option<Ipv4Addr>, metric: u32) -> RouteMessage {
    let mut builder = RouteMessageBuilder::<Ipv4Addr>::new()
        .destination_prefix(route.destination, route.prefix_len)
        .output_interface(index)
        .priority(metric)
        .protocol(RouteProtocol::Dhcp);
    builder = match route.gateway {
        Some(gateway) => builder.gateway(gateway),
        None => builder.scope(RouteScope::Link),
    };
    if let Some(source) = source {
        builder = builder.pref_source(source);
    }
    builder.build()
}

/// Treats "no such address/route" as success, for idempotent removals.
fn ignore_missing(result: Result<(), rtnetlink::Error>) -> Result<(), rtnetlink::Error> {
    match result {
        Err(rtnetlink::Error::NetlinkError(err))
            if [Errno::SRCH, Errno::ADDRNOTAVAIL, Errno::NOENT]
                .iter()
                .any(|errno| err.raw_code() == -errno.raw_os_error()) =>
        {
            Ok(())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::symlink;

    use rtnetlink::packet_route::route::{RouteAddress, RouteAttribute};

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
                symlink(&device, dir.join("device")).unwrap();
            }
            dir
        };
        add("ens4", 1, true);
        add("eth0", 1, true);
        add("ib0", 32, true);
        add("lo", 772, false);
        add("docker0", 1, false);
        fs::create_dir(add("wlan0", 1, true).join("phy80211")).unwrap();
        assert_eq!(physical_ethernet(&net).unwrap(), ["ens4", "eth0"]);
    }

    #[test]
    fn builds_route_messages() {
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        let default = Route {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
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
            prefix_len: 32,
            gateway: None,
        };
        let msg = route_message(3, &on_link, None, 1024);
        assert_eq!(msg.header.scope, RouteScope::Link);
        assert_eq!(msg.header.destination_prefix_length, 32);
        assert!(!msg.attributes.iter().any(|a| matches!(a, RouteAttribute::Gateway(_))));
    }
}

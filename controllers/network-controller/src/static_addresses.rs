//! Addresses configured statically on an interface, and its default route through their
//! gateway (routes of protocol `static`, beside DHCP's `dhcp`).

use std::net::Ipv4Addr;

use netlink_packet_route::route::RouteProtocol;
use network_controller::Ipv4Address;
use network_controller::StaticIpv4;

use crate::dhcp::Route;
use crate::link::Link;
use crate::link::Netlink;
use crate::prefix_len::PrefixLen;

/// Configures `addresses` on `link`, its routes of `metric`: all of it, or nothing (what was
/// added is removed again before the error is returned).
pub async fn apply(
    netlink: &Netlink,
    link: &Link,
    addresses: &StaticIpv4,
    metric: u32,
) -> anyhow::Result<()> {
    let mut added = Vec::new();
    let mut result = Ok(());
    for address in addresses.addresses() {
        result = netlink
            .replace_static_address(link, address.address(), prefix_len(address), metric)
            .await;
        if result.is_err() {
            break;
        }
        added.push(*address);
    }
    if result.is_ok()
        && let Some((route, source)) = default_route(addresses)
    {
        result = netlink
            .replace_route(link, &route, source, metric, RouteProtocol::Static)
            .await;
    }
    if result.is_err() {
        for address in added.iter().rev() {
            log_error(
                netlink
                    .delete_address(link, address.address(), prefix_len(address))
                    .await,
            );
        }
    }
    result
}

/// Removes `addresses` and their default route from `link`, as far as it can: errors are
/// logged.
pub async fn remove(netlink: &Netlink, link: &Link, addresses: &StaticIpv4, metric: u32) {
    if let Some((route, _)) = default_route(addresses) {
        log_error(
            netlink
                .delete_route(link, &route, metric, RouteProtocol::Static)
                .await,
        );
    }
    for address in addresses.addresses().iter().rev() {
        log_error(
            netlink
                .delete_address(link, address.address(), prefix_len(address))
                .await,
        );
    }
}

/// The default route of `addresses`, and its source, if they have a gateway.
#[must_use]
fn default_route(addresses: &StaticIpv4) -> Option<(Route, Ipv4Addr)> {
    let route = Route {
        destination: Ipv4Addr::UNSPECIFIED,
        prefix_len: PrefixLen::ZERO,
        gateway: Some(addresses.gateway()?),
    };
    Some((route, addresses.gateway_source()?))
}

#[must_use]
fn prefix_len(address: &Ipv4Address) -> PrefixLen {
    // Ipv4Address holds 1 to 32.
    PrefixLen::new(address.prefix_len()).unwrap_or(PrefixLen::HOST)
}

fn log_error(result: anyhow::Result<()>) {
    if let Err(err) = result {
        tracing::error!(
            error = format!("{err:#}"),
            "removing a static configuration"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routes_through_the_gateway() {
        let addresses = StaticIpv4::new(
            vec![
                "10.0.0.5/32".parse().unwrap(),
                "192.0.2.10/24".parse().unwrap(),
            ],
            Some(Ipv4Addr::new(192, 0, 2, 1)),
        )
        .unwrap();
        let (route, source) = default_route(&addresses).unwrap();
        assert_eq!(route.prefix_len, PrefixLen::ZERO);
        assert_eq!(route.gateway, Some(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(source, Ipv4Addr::new(192, 0, 2, 10));
        let without = StaticIpv4::new(vec!["192.0.2.10/24".parse().unwrap()], None).unwrap();
        assert!(default_route(&without).is_none());
    }
}

//! DHCP on one interface: its client runs forever, and each lease it gets or loses is applied to
//! the interface and to the [`Shared`] state.

use std::sync::Arc;
use std::time::Duration;

use tokio::task::JoinHandle;

use crate::dhcp;
use crate::dhcp::Client;
use crate::dhcp::Lease;
use crate::dhcp::Outcome;
use crate::link::Link;
use crate::link::Netlink;
use crate::link_events::LinkState;
use crate::raw_socket::RawSocket;
use crate::shared::Shared;

/// Metric of the primary interface's routes; other interfaces get [`METRIC_STEP`] more per rank
/// so that the primary default route wins and secondary ones never replace each other.
const BASE_METRIC: u32 = 1024;
const METRIC_STEP: u32 = 100;

/// How long to wait for the carrier after bringing an interface up before starting DHCP anyway.
const CARRIER_TIMEOUT: Duration = Duration::from_secs(5);

/// Brings `link` up and spawns its DHCP client, which runs until aborted; `None` when it cannot
/// run.
#[must_use]
pub async fn start(
    shared: &Arc<Shared>,
    netlink: &Netlink,
    link: &LinkState,
) -> Option<JoinHandle<()>> {
    let Some(mac) = link.mac else {
        tracing::error!(interface = %link.name, "no Ethernet address");
        return None;
    };
    if let Err(err) = netlink.set_up(&link.name).await {
        tracing::error!(
            interface = %link.name,
            error = format!("{err:#}"),
            "cannot set the link up"
        );
        return None;
    }
    let link = Link {
        name: link.name.clone(),
        index: link.index,
        mac,
    };
    Some(tokio::spawn(run_dhcp(
        Arc::clone(shared),
        netlink.clone(),
        link,
    )))
}

/// Runs DHCP on `link` forever, applying leases as they come and go. Aborted when the link
/// disappears, which takes its addresses and routes with it.
async fn run_dhcp(shared: Arc<Shared>, netlink: Netlink, link: Link) {
    if !netlink.wait_for_carrier(&link, CARRIER_TIMEOUT).await {
        tracing::warn!(
            interface = %link.name,
            "no carrier after {CARRIER_TIMEOUT:?}, trying DHCP anyway"
        );
    }
    let socket = loop {
        match dhcp::bind(&link.name, dhcp::CLIENT_PORT) {
            Ok(socket) => break socket,
            Err(err) => {
                tracing::error!(interface = %link.name, error = %err, "DHCP socket");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    };
    let client = Client::new(link.mac, link.name.clone());
    let mut rank = None;
    loop {
        let mut lease = acquire(&client, &link).await;
        let rank = *rank.get_or_insert_with(|| shared.next_rank());
        let metric = BASE_METRIC.saturating_add(rank.saturating_mul(METRIC_STEP));
        tracing::info!(
            interface = %link.name,
            "DHCP: bound to {}/{} from {} ({})",
            lease.address,
            lease.prefix_len,
            lease.server,
            if rank == 0 { "primary" } else { "secondary" },
        );
        apply_lease(&netlink, &link, None, &lease, metric).await;
        shared.bind(rank, link.index, &link.name, lease.clone());
        loop {
            match client.maintain(&socket, &lease).await {
                Outcome::Renewed(renewed) => {
                    let renewed = *renewed;
                    tracing::debug!(
                        interface = %link.name,
                        "DHCP: lease of {} renewed",
                        renewed.address
                    );
                    apply_lease(&netlink, &link, Some(&lease), &renewed, metric).await;
                    shared.bind(rank, link.index, &link.name, renewed.clone());
                    lease = renewed;
                }
                Outcome::Nak(nak) => {
                    tracing::warn!(
                        interface = %link.name,
                        "DHCP: lease of {} revoked: {nak}",
                        lease.address
                    );
                    break;
                }
                Outcome::Expired => {
                    tracing::warn!(
                        interface = %link.name,
                        "DHCP: lease of {} expired",
                        lease.address
                    );
                    break;
                }
            }
        }
        remove_lease(&netlink, &link, &lease, metric).await;
        shared.unbind(rank);
    }
}

/// Acquires a lease over a packet socket, opened only for that long.
async fn acquire(client: &Client, link: &Link) -> Lease {
    loop {
        match RawSocket::open(link.index) {
            Ok(socket) => return client.acquire(&socket).await,
            Err(err) => {
                tracing::error!(interface = %link.name, error = %err, "DHCP packet socket");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

/// Configures `new` on `link`, removing what `old` configured and `new` does not. Errors are
/// logged: a partially applied lease is still better than none, and it is retried on renewal.
async fn apply_lease(
    netlink: &Netlink,
    link: &Link,
    old: Option<&Lease>,
    new: &Lease,
    metric: u32,
) {
    let routes = new.routes();
    if let Some(old) = old {
        let moved = (old.address, old.prefix_len) != (new.address, new.prefix_len);
        for route in old.routes().iter().rev() {
            if moved || !routes.contains(route) {
                log_error(netlink.delete_route(link, route, metric).await);
            }
        }
        if moved {
            log_error(
                netlink
                    .delete_address(link, old.address, old.prefix_len)
                    .await,
            );
        }
    }
    if let Some(mtu) = new.mtu
        && old.is_none_or(|old| old.mtu != new.mtu)
    {
        log_error(netlink.set_mtu(link, mtu).await);
    }
    log_error(netlink.replace_address(link, new, metric).await);
    for route in &routes {
        log_error(
            netlink
                .replace_route(link, route, new.address, metric)
                .await,
        );
    }
}

async fn remove_lease(netlink: &Netlink, link: &Link, lease: &Lease, metric: u32) {
    for route in lease.routes().iter().rev() {
        log_error(netlink.delete_route(link, route, metric).await);
    }
    log_error(
        netlink
            .delete_address(link, lease.address, lease.prefix_len)
            .await,
    );
}

fn log_error(result: anyhow::Result<()>) {
    if let Err(err) = result {
        tracing::error!(error = format!("{err:#}"), "configuring the interface");
    }
}

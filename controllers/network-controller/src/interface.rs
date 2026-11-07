//! DHCP on one interface: its client runs until stopped, and each lease it gets or loses is
//! applied to the interface and to the [`Shared`] state.

use std::future;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use netlink_packet_route::route::RouteProtocol;
use network_controller::Mtu;
use tokio::sync::oneshot;
use tokio::sync::watch;
use tokio::task::JoinError;
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

/// The metric of the routes of the interface of `rank`, whether DHCP or a static configuration
/// set them up.
#[must_use]
pub fn metric(rank: u32) -> u32 {
    BASE_METRIC.saturating_add(rank.saturating_mul(METRIC_STEP))
}

/// The DHCP client of an interface, running until stopped or aborted.
pub struct DhcpTask {
    task: JoinHandle<Option<u32>>,
    stop: oneshot::Sender<()>,
    /// Counts the times the carrier came back.
    carrier: watch::Sender<u64>,
}

impl DhcpTask {
    /// Tells the client the link's carrier came back: the link may be on another network now (a
    /// Wi-Fi station associated elsewhere, a cable plugged elsewhere). Bound, it checks its lease
    /// (INIT-REBOOT); still discovering, it starts over at once rather than at its next
    /// retransmission.
    pub fn carrier_regained(&self) {
        self.carrier
            .send_modify(|count| *count = count.wrapping_add(1));
    }

    /// Stops the client: it gives its lease's addresses and routes up, then ends. Returns the
    /// interface's rank, if it got one, for a later configuration to keep it.
    pub async fn stop(self) -> Result<Option<u32>, JoinError> {
        // Ended already if it cannot be told.
        let _ = self.stop.send(());
        self.task.await
    }

    /// Aborts the client, its lease left as it is: the interface is gone, and the kernel removed
    /// its addresses and routes with it. Returns once the client no longer runs.
    pub async fn abort(self) -> Result<(), JoinError> {
        self.task.abort();
        match self.task.await {
            Ok(_) => Ok(()),
            Err(error) if error.is_cancelled() => Ok(()),
            Err(error) => Err(error),
        }
    }

    /// How many times the client was told the carrier came back.
    #[cfg(test)]
    #[must_use]
    pub fn carrier_regained_count(&self) -> u64 {
        *self.carrier.borrow()
    }

    /// A client already started, as `task`, told to stop through `stop`.
    #[cfg(test)]
    #[must_use]
    pub fn from_parts(task: JoinHandle<Option<u32>>, stop: oneshot::Sender<()>) -> Self {
        let (carrier, _) = watch::channel(0);
        Self {
            task,
            stop,
            carrier,
        }
    }
}

/// What a DHCP client keeps from the interface's configuration.
#[derive(Debug, Clone, Copy, Default)]
pub struct DhcpOptions {
    /// The interface's rank, kept from an earlier configuration; the next free one otherwise,
    /// with the first lease.
    pub rank: Option<u32>,
    /// The configured MTU, which replaces DHCP's (option 26).
    pub mtu: Option<Mtu>,
}

/// Brings `link` up and spawns its DHCP client, which runs until stopped or aborted.
pub async fn start(
    shared: &Arc<Shared>,
    netlink: &Netlink,
    link: &LinkState,
    options: DhcpOptions,
) -> anyhow::Result<DhcpTask> {
    let mac = link
        .mac
        .with_context(|| format!("{} has no Ethernet address", link.name))?;
    netlink.set_up(&link.name).await?;
    let link = Link {
        name: link.name.clone(),
        index: link.index,
        mac,
    };
    if let Some(mtu) = options.mtu {
        netlink.set_mtu(&link, mtu.get()).await?;
    }
    let (stop, stopped) = oneshot::channel();
    let (carrier, regained) = watch::channel(0);
    let task = tokio::spawn(run_dhcp(
        Arc::clone(shared),
        netlink.clone(),
        link,
        options,
        stopped,
        regained,
    ));
    Ok(DhcpTask {
        task,
        stop,
        carrier,
    })
}

/// `future`'s output, or `None` once `stop` fires (or its sender is gone) first.
async fn unless_stopped<T>(
    stop: &mut oneshot::Receiver<()>,
    future: impl Future<Output = T>,
) -> Option<T> {
    tokio::select! {
        output = future => Some(output),
        _ = stop => None,
    }
}

/// Returns when the carrier comes back (as [`DhcpTask::carrier_regained`] tells); never once
/// the task is gone.
async fn carrier_regained(carrier: &mut watch::Receiver<u64>) {
    if carrier.changed().await.is_err() {
        future::pending::<()>().await;
    }
}

/// What ended a bound lease's wait.
enum Bound {
    Maintained(Outcome),
    CarrierRegained,
}

/// Runs DHCP on `link` until stopped, applying leases as they come and go; stopped, removes its
/// lease from the interface and returns its rank. Only waits are interrupted: a lease is never
/// applied halfway. Aborted when the link disappears, which takes its addresses and routes with
/// it. When the carrier comes back, a lease is checked again (INIT-REBOOT, then discovery if no
/// server answers), and a discovery in progress starts over.
async fn run_dhcp(
    shared: Arc<Shared>,
    netlink: Netlink,
    link: Link,
    options: DhcpOptions,
    mut stop: oneshot::Receiver<()>,
    mut regained: watch::Receiver<u64>,
) -> Option<u32> {
    let mut rank = options.rank;
    let carrier = netlink.wait_for_carrier(&link, CARRIER_TIMEOUT);
    match unless_stopped(&mut stop, carrier).await {
        Some(true) => {}
        Some(false) => tracing::warn!(
            interface = %link.name,
            "no carrier after {CARRIER_TIMEOUT:?}, trying DHCP anyway"
        ),
        None => return rank,
    }
    // The carrier that came while waiting for it is the one DHCP starts with.
    regained.borrow_and_update();
    let socket = loop {
        match dhcp::bind(&link.name, dhcp::CLIENT_PORT) {
            Ok(socket) => break socket,
            Err(err) => {
                tracing::error!(interface = %link.name, error = %err, "DHCP socket");
                let retry = tokio::time::sleep(Duration::from_secs(10));
                unless_stopped(&mut stop, retry).await?;
            }
        }
    };
    let client = Client::new(link.mac, link.name.clone());
    let overridden_mtu = options.mtu.is_some();
    loop {
        let acquired = unless_stopped(&mut stop, acquire(&client, &link, &mut regained)).await;
        let Some(mut lease) = acquired else {
            return rank;
        };
        let rank = *rank.get_or_insert_with(|| shared.next_rank());
        let metric = metric(rank);
        tracing::info!(
            interface = %link.name,
            "DHCP: bound to {}/{} from {} ({})",
            lease.address,
            lease.prefix_len,
            lease.server,
            if rank == 0 { "primary" } else { "secondary" },
        );
        apply_lease(&netlink, &link, None, &lease, metric, overridden_mtu).await;
        shared.bind(rank, link.index, &link.name, lease.clone());
        loop {
            let bound = async {
                tokio::select! {
                    outcome = client.maintain(&socket, &lease) => Bound::Maintained(outcome),
                    () = carrier_regained(&mut regained) => Bound::CarrierRegained,
                }
            };
            let outcome = match unless_stopped(&mut stop, bound).await {
                Some(Bound::Maintained(outcome)) => Some(outcome),
                Some(Bound::CarrierRegained) => {
                    tracing::info!(
                        interface = %link.name,
                        "DHCP: carrier regained, checking the lease of {}",
                        lease.address
                    );
                    match unless_stopped(&mut stop, reboot(&client, &link, &lease)).await {
                        Some(Some(outcome)) => Some(outcome),
                        Some(None) => {
                            tracing::info!(
                                interface = %link.name,
                                "DHCP: no answer about the lease of {}, discovering",
                                lease.address
                            );
                            break;
                        }
                        None => None,
                    }
                }
                None => None,
            };
            let Some(outcome) = outcome else {
                tracing::info!(
                    interface = %link.name,
                    "DHCP: stopped, giving up the lease of {}",
                    lease.address
                );
                remove_lease(&netlink, &link, &lease, metric).await;
                shared.unbind(rank);
                return Some(rank);
            };
            match outcome {
                Outcome::Renewed(renewed) => {
                    let renewed = *renewed;
                    tracing::debug!(
                        interface = %link.name,
                        "DHCP: lease of {} renewed",
                        renewed.address
                    );
                    apply_lease(
                        &netlink,
                        &link,
                        Some(&lease),
                        &renewed,
                        metric,
                        overridden_mtu,
                    )
                    .await;
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

/// Acquires a lease over a packet socket, opened only for that long; starts over when the
/// carrier comes back.
async fn acquire(client: &Client, link: &Link, carrier: &mut watch::Receiver<u64>) -> Lease {
    loop {
        match RawSocket::open(link.index) {
            Ok(socket) => {
                tokio::select! {
                    lease = client.acquire(&socket) => return lease,
                    () = carrier_regained(carrier) => {
                        tracing::debug!(interface = %link.name, "DHCP: carrier regained, discovering");
                    }
                }
            }
            Err(err) => {
                tracing::error!(interface = %link.name, error = %err, "DHCP packet socket");
                tokio::time::sleep(Duration::from_secs(10)).await;
            }
        }
    }
}

/// Checks `lease` after the carrier came back (INIT-REBOOT) over a packet socket, opened only
/// for that long: the link may have no address of the network it is on now. `None` if no server
/// answered (or the socket cannot be opened), for discovery to start over.
async fn reboot(client: &Client, link: &Link, lease: &Lease) -> Option<Outcome> {
    match RawSocket::open(link.index) {
        Ok(socket) => client.reboot(&socket, lease).await,
        Err(err) => {
            tracing::error!(interface = %link.name, error = %err, "DHCP packet socket");
            None
        }
    }
}

/// Configures `new` on `link`, removing what `old` configured and `new` does not; its MTU
/// unless `overridden_mtu` (the configuration's applies). Errors are logged: a partially applied
/// lease is still better than none, and it is retried on renewal.
async fn apply_lease(
    netlink: &Netlink,
    link: &Link,
    old: Option<&Lease>,
    new: &Lease,
    metric: u32,
    overridden_mtu: bool,
) {
    let routes = new.routes();
    if let Some(old) = old {
        let moved = (old.address, old.prefix_len) != (new.address, new.prefix_len);
        for route in old.routes().iter().rev() {
            if moved || !routes.contains(route) {
                log_error(
                    netlink
                        .delete_route(link, route, metric, RouteProtocol::Dhcp)
                        .await,
                );
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
        && !overridden_mtu
        && old.is_none_or(|old| old.mtu != new.mtu)
    {
        log_error(netlink.set_mtu(link, mtu).await);
    }
    log_error(netlink.replace_address(link, new, metric).await);
    for route in &routes {
        log_error(
            netlink
                .replace_route(link, route, new.address, metric, RouteProtocol::Dhcp)
                .await,
        );
    }
}

async fn remove_lease(netlink: &Netlink, link: &Link, lease: &Lease, metric: u32) {
    for route in lease.routes().iter().rev() {
        log_error(
            netlink
                .delete_route(link, route, metric, RouteProtocol::Dhcp)
                .await,
        );
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

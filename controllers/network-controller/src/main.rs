//! network-controller: DHCPv4 on every physical Ethernet interface (with lease renewal), IPv6
//! SLAAC left to the kernel, and the resolver configuration. A sandboxed service of serviced.
//!
//! It writes `/run/hardened/resolv.conf`, which `/etc/resolv.conf` on the read-only root links
//! to, and serves `hardened.network.v1.NetworkController`: machine-controller configures the DNS
//! override through it and reads what DHCP offered. It reports its readiness to serviced (notify
//! protocol) once an interface got a lease, or the attempts timed out.

mod dhcp;
mod dhcp_message;
mod dhcp_option;
mod domain_search;
mod interface;
mod interfaces;
mod link;
mod link_events;
mod netlink_socket;
mod network_service;
mod options;
mod persisted_state;
mod prefix_len;
mod raw_socket;
mod resolv_conf;
mod run;
mod shared;

use std::env;
use std::io;

use anyhow::Context as _;
use libserviced::activation::Sockets;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::options::Options;

/// One thread: the work is mostly waiting, and the sandbox caps its tasks.
#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    use std::io::IsTerminal as _;

    let filter = env::var("RUST_LOG")
        .ok()
        .and_then(|directives| directives.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    let logs = tracing_subscriber::fmt().with_writer(io::stderr);
    if io::stderr().is_terminal() {
        logs.finish().with(filter).init();
    } else {
        // Run by serviced, which timestamps the lines it forwards to its own log.
        logs.with_ansi(false)
            .without_time()
            .with_target(false)
            .finish()
            .with(filter)
            .init();
    }

    let mut sockets = Sockets::from_env().context("taking the sockets serviced passed")?;
    let api = sockets.take("api").context("taking the API's socket")?;
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;
    let mut terminate = unix::signal(SignalKind::terminate())?;
    let options = Options::default();
    // Leases need no release: the addresses stay until they expire, or a new run renews them.
    tokio::select! {
        result = run::run(options, api, serviced) => match result? {},
        _ = terminate.recv() => tracing::info!("terminating"),
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
    }
    Ok(())
}

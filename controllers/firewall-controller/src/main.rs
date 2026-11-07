//! firewall-controller: the firewall's policy, a service of serviced sandboxed with only
//! `CAP_NET_ADMIN` (and `CAP_SYSLOG`, to read what it blocked in the kernel's log). It relies on
//! nothing but the kernel's nf_tables, which it speaks over netlink: no nft program.
//!
//! It applies its configuration at start (before the network comes up: the network's service
//! requires it) as the nftables table `inet firewall-controller`, in one nf_tables transaction:
//! the one it kept (`/var/lib/firewall-controller` when the sandbox has it, its runtime directory
//! otherwise), else the system's default (`/usr/lib/firewall-controller/default.json`), else the
//! built-in one (on, nothing let in). It takes changes through
//! `hardened.firewall.v1.FirewallController` from the root processes of the services its socket
//! allows, and reports its readiness to serviced (notify protocol) once applied: the network fails
//! closed, but on a kernel without nf_tables, where nothing can be filtered.

mod firewall_service;
mod kmsg;
mod options;
mod persisted_state;
mod run;

use std::env;
use std::io;

use anyhow::Context as _;
use libserviced::activation::Sockets;
use options::Options;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

/// One thread, and the netlink requests on blocking ones: the sandbox caps its tasks.
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
    tokio::select! {
        result = run::run(Options::default(), api, serviced) => match result? {},
        _ = terminate.recv() => tracing::info!("terminating"),
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
    }
    Ok(())
}

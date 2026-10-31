//! time-controller: an SNTP client keeping the clock in sync, a service of serviced sandboxed
//! with only `CAP_SYS_TIME`.
//!
//! machine-controller configures its servers through `hardened.time.v1.TimeController`; until
//! then (and without a persisted configuration) it does not poll. Every poll interval, it
//! resolves its servers, queries all their addresses at once, and corrects the clock with the
//! reply closest to its reference clock. It reports its readiness to serviced (notify protocol)
//! once the clock is synchronized, or 30 s after being configured without.

mod client;
mod clock;
mod measurement;
mod packet;
mod persisted_state;
mod poller;
mod ptp;
mod ready;
mod run;
mod sync_status;
mod time_service;

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

/// One thread, and resolutions on blocking ones: the sandbox caps its tasks.
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
    let state_file = run::STATE_FILE.into();
    tokio::select! {
        result = run::run(state_file, api, serviced) => match result? {},
        _ = terminate.recv() => tracing::info!("terminating"),
        _ = tokio::signal::ctrl_c() => tracing::info!("interrupted"),
    }
    Ok(())
}

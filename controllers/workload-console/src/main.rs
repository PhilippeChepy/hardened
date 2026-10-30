//! workload-console: runs processes in workloads' containers with `ctr tasks exec`, for
//! workload-controller's `Workloads/Exec`. Unconfined, as `ctr` needs containerd's socket, so
//! workload-controller, which parses the API's requests, stays confined.

mod console_service;
mod daemon;
mod pty;
mod session;

use std::env;
use std::io;

use anyhow::Context as _;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

fn main() -> anyhow::Result<()> {
    let filter = env::var("RUST_LOG")
        .ok()
        .and_then(|directives| directives.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    // serviced timestamps the lines it writes to the service's log.
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .finish()
        .with(filter)
        .init();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?
        .block_on(daemon::run())
}

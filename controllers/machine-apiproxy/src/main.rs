//! machine-apiproxy: the machine's API (`hardened.machine.v1`, `hardened.workloads.v1` and
//! `hardened.attestation.v1`) over mutual TLS.
//!
//! machine-controller configures it
//! ([`ConfigurationService`](configuration_service::ConfigurationService)) with its address and
//! TLS identity. The client certificate's Organization gives its
//! [`Role`](machine_apiproxy::Role), checked on every call; authorized calls are forwarded
//! unchanged to machine-controller's socket, which serves them. machine-apiproxy parses TLS from
//! the network, so it sees nothing else.

mod access_log;
mod api_listener;
mod authz;
mod configuration_service;
mod daemon;
mod server;
mod state;
mod tls;

use std::env;
use std::io;
use std::io::IsTerminal;

use anyhow::Context;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

fn main() -> anyhow::Result<()> {
    let filter = env::var("RUST_LOG")
        .ok()
        .and_then(|directives| directives.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    let logs = tracing_subscriber::fmt().with_writer(io::stderr);
    if io::stderr().is_terminal() {
        logs.finish().with(filter).init();
    } else {
        // Run by serviced, which timestamps the lines it writes to the service's log.
        logs.with_ansi(false)
            .without_time()
            .finish()
            .with(filter)
            .init();
    }

    // Bounded threads: the sandbox caps the tasks, whatever the machine's CPUs.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .max_blocking_threads(16)
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(daemon::run())
}

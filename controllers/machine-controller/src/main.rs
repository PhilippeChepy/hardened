//! machine-controller: sets the instance up from its platform's metadata and user-data, configures
//! the controllers through their APIs, then serves the machine's API (`hardened.machine.v1`,
//! `hardened.workloads.v1` and `hardened.attestation.v1`) to machine-apiproxy.
//!
//! A daemon of serviced, unconfined, started once network-controller has configured the network.
//! It fails only when the machine cannot boot: any other problem is logged and worked around.

mod check;
mod configuration;
mod containerd;
mod controllers;
mod daemon;
#[cfg(test)]
mod fake_controllers;
mod hostnames;
mod hosts;
mod kmod;
mod machine_api;
mod machine_identity;
mod metadata;
mod services_api;
mod setup;
mod state;
mod sysctl;
mod time_servers;

use std::env;
use std::io;
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process;

use anyhow::Context;
use clap::Parser;
use clap::Subcommand;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[derive(Parser)]
#[command(
    version,
    about = "Sets a hardened instance up from its platform's metadata and user-data, and serves \
             the machine's API"
)]
struct Cli {
    /// Without one, runs as serviced's service.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Validates a user-data file and prints the effective settings.
    CheckUserData { path: PathBuf },
}

fn main() -> anyhow::Result<()> {
    if let Some(Command::CheckUserData { path }) = Cli::parse().command {
        return check::run(&path);
    }
    init_logging();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")?;
    if let Err(e) = runtime.block_on(daemon::run()) {
        tracing::error!("{e:#}");
        process::exit(1);
    }
    Ok(())
}

fn init_logging() {
    let filter = env::var("RUST_LOG")
        .ok()
        .and_then(|directives| directives.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    let logs = tracing_subscriber::fmt().with_writer(io::stderr);
    if io::stderr().is_terminal() {
        logs.finish().with(filter).init();
    } else {
        // Run by serviced, which timestamps the lines it forwards.
        logs.with_ansi(false)
            .without_time()
            .with_target(false)
            .finish()
            .with(filter)
            .init();
    }
}

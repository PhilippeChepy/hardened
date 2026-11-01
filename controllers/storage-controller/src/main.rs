//! storage-controller: sets the state partition up and mounts it on `/var`, once configured.
//!
//! An unconfined, socket-activated daemon of serviced (it mounts and opens dm-crypt devices).
//! machine-controller's first `Configure` call starts it: it grows the partition with the disk,
//! unlocks it with the key trust-controller unseals (or formats it) when encrypted, mounts it
//! ([`partition`]) and creates the directory of the services' logs there ([`setup`]), then
//! reports ready. Its `stop` command, run by serviced once it is gone, undoes that ([`stop`]).
//!
//! It fails only when `/var` cannot even be a tmpfs: any other problem is logged and worked
//! around.

mod backing;
mod daemon;
mod encryption;
mod mount;
mod partition;
mod setup;
mod state;
mod stop;
mod storage_service;

use std::env;
use std::io;
use std::process;

use anyhow::Context as _;
use clap::Parser;
use clap::Subcommand;
use tracing::Level;
use tracing::error;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

#[derive(Parser)]
#[command(version, about = "Sets the state partition up and mounts it on /var")]
struct Cli {
    /// Without one, serves the API (run by serviced).
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Unmounts `/var` and closes the encrypted partition (run by serviced once the daemon is
    /// gone).
    Stop,
}

fn main() {
    let cli = Cli::parse();
    init_logging();
    let result = match cli.command {
        None => serve(),
        Some(Command::Stop) => stop::run(),
    };
    if let Err(e) = result {
        error!(error = format!("{e:#}"), "storage-controller failed");
        process::exit(1);
    }
}

fn serve() -> anyhow::Result<()> {
    // The main thread drives the runtime's I/O while setting up blocks another, which calls
    // trust-controller through it.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?;
    runtime.block_on(daemon::run())
}

fn init_logging() {
    use std::io::IsTerminal as _;

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
            .with_target(false)
            .finish()
            .with(filter)
            .init();
    }
}

//! dust-init: PID 1 of the hardened OS.
//!
//! Run as PID 1 it boots the machine (see [`init`]). Run as a regular process it offers
//! development helpers, e.g. validating a user-data file.

mod api;
mod attestation;
mod control;
mod init;
mod logging;
mod machine;
mod net;
mod ntp;
mod platform;
mod power;
mod process;
mod sandbox;
mod settings;
mod storage;
mod types;
mod workloads;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "PID 1 of the hardened OS")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validates a user-data file and prints the effective settings.
    CheckUserData { path: PathBuf },
}

fn main() -> anyhow::Result<()> {
    if rustix::process::getpid().is_init() {
        init::run();
    }

    match Cli::parse().command {
        Command::CheckUserData { path } => {
            let raw = std::fs::read(&path)?;
            let user_data = settings::UserData::parse(&raw)?;
            print!("{}", toml::to_string_pretty(&user_data.settings)?);
        }
    }
    Ok(())
}

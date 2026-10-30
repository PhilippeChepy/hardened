//! The command line, and the dispatch of its commands.

use std::process::ExitCode;

use clap::Parser;
use clap::Subcommand;

use crate::attest;
use crate::client;
use crate::machine;
use crate::pki;
use crate::services;
use crate::workloads;

#[derive(Parser)]
#[command(version, about = "Operator CLI of the hardened OS")]
pub struct Cli {
    #[command(flatten)]
    connection: client::ConnectionArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Shows the client version and the machine's OS and identity.
    Version,
    /// Prints serviced's own log.
    Logs {
        /// Keeps streaming new entries.
        #[arg(short, long)]
        follow: bool,
        /// Number of past entries to print first (0: all retained).
        #[arg(long, default_value_t = 0)]
        tail: u32,
    },
    /// Prints the effective settings as TOML, secrets redacted.
    Settings,
    /// Shows what backs /var: the state partition (plain or encrypted) or a tmpfs, and why.
    Storage,
    /// Shows whether the clock is synchronized, and the NTP client's last correction.
    Time,
    /// Reboots the machine.
    Reboot,
    /// Powers the machine off.
    Shutdown,
    /// Manages serviced's services.
    #[command(subcommand, alias = "services")]
    Service(services::Command),
    /// Manages workloads (containers).
    #[command(subcommand)]
    Workloads(workloads::Command),
    /// Fetches remote attestation evidence from the TPM.
    #[command(subcommand)]
    Attest(attest::Command),
    /// Generates certificates for machine-apiproxy and its clients (offline).
    #[command(subcommand)]
    Pki(pki::Command),
}

/// Runs the command `cli` gives, and the code to exit with.
pub async fn run(cli: Cli) -> anyhow::Result<ExitCode> {
    let connection = &cli.connection;
    match cli.command {
        Command::Pki(command) => pki::run(command)?,
        Command::Version => machine::version(client::connect(connection).await?).await?,
        Command::Logs { follow, tail } => {
            machine::logs(client::connect(connection).await?, follow, tail).await?;
        }
        Command::Settings => machine::settings(client::connect(connection).await?).await?,
        Command::Storage => machine::storage(client::connect(connection).await?).await?,
        Command::Time => machine::time(client::connect(connection).await?).await?,
        Command::Reboot => machine::reboot(client::connect(connection).await?).await?,
        Command::Shutdown => machine::shutdown(client::connect(connection).await?).await?,
        Command::Service(command) => {
            services::run(client::connect(connection).await?, command).await?;
        }
        Command::Workloads(command) => {
            return workloads::run(client::connect(connection).await?, command).await;
        }
        Command::Attest(command) => {
            attest::run(client::connect(connection).await?, command).await?;
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn cli_is_consistent() {
        Cli::command().debug_assert();
    }
}

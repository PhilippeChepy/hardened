//! hctl: operator CLI of the hardened OS.
//!
//! Talks to dust-init through `dust-api` over mTLS, and generates the PKI both sides need.

mod args;
mod attest;
mod client;
mod machine;
mod pki;
mod workloads;

use std::io;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(version, about = "Operator CLI of the hardened OS")]
struct Cli {
    #[command(flatten)]
    connection: client::ConnectionArgs,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Shows the client version and the machine's OS and identity.
    Version,
    /// Prints dust-init's own log.
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
    /// Manages workloads (containers).
    #[command(subcommand)]
    Workloads(workloads::Command),
    /// Fetches remote attestation evidence from the TPM.
    #[command(subcommand)]
    Attest(attest::Command),
    /// Generates certificates for dust-api and its clients (offline).
    #[command(subcommand)]
    Pki(pki::Command),
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match run(Cli::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        // `hctl logs | head` closing the pipe is not a failure.
        Err(error) if is_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> anyhow::Result<()> {
    let connection = &cli.connection;
    match cli.command {
        Command::Pki(command) => pki::run(command),
        Command::Version => machine::version(client::connect(connection).await?).await,
        Command::Logs { follow, tail } => machine::logs(client::connect(connection).await?, follow, tail).await,
        Command::Settings => machine::settings(client::connect(connection).await?).await,
        Command::Storage => machine::storage(client::connect(connection).await?).await,
        Command::Time => machine::time(client::connect(connection).await?).await,
        Command::Reboot => machine::reboot(client::connect(connection).await?).await,
        Command::Shutdown => machine::shutdown(client::connect(connection).await?).await,
        Command::Workloads(command) => workloads::run(client::connect(connection).await?, command).await,
        Command::Attest(command) => attest::run(client::connect(connection).await?, command).await,
    }
}

fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    #[test]
    fn cli_is_consistent() {
        super::Cli::command().debug_assert();
    }
}

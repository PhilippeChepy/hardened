//! hctl: operator CLI of the hardened OS.
//!
//! Talks to `machine-apiproxy` over mTLS, and generates the PKI both sides need.

mod args;
mod attest;
mod cli;
mod client;
mod exec;
mod machine;
mod pki;
mod services;
mod settings_toml;
mod table;
mod workloads;

use std::io;
use std::process::ExitCode;

use clap::Parser as _;

use crate::cli::Cli;

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    match cli::run(Cli::parse()).await {
        Ok(code) => code,
        // `hctl logs | head` closing the pipe is not a failure.
        Err(error) if is_broken_pipe(&error) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

#[must_use]
fn is_broken_pipe(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<io::Error>()
        .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
}

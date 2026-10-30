//! trust-controller: the TPM's only user. On the socket serviced activates it with, it serves
//! attestation evidence (`hardened.attestation.v1.Attestation`: PCR values, the event log,
//! quotes) to machine-controller, and seals secrets to the booted image
//! (`hardened.trust.v1.Sealing`) for storage-controller.
//!
//! It holds the TPM so that neither machine-apiproxy, which parses TLS from the network, nor
//! storage-controller, which is unconfined, does. Without a TPM, serviced never starts it and its
//! socket does not exist.

mod access;
mod attestation_service;
mod commands;
mod daemon;
mod hash_alg;
mod marshal;
mod response_code;
mod sealed_object;
mod sealing_service;
mod shared_tpm;
mod tpm;
mod tpm_error;
mod transport;

use std::env;
use std::io;

use anyhow::Context as _;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

fn main() -> anyhow::Result<()> {
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

    // Few threads: TPM commands are serialized anyway, and the sandbox caps the tasks.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(4)
        .build()
        .context("starting the runtime")?;
    runtime.block_on(daemon::run())
}

//! The daemon serving the socket's APIs from the TPM.

use std::time::Duration;

use anyhow::Context as _;
use controllers_helpers::idle::Idle;
use libserviced::activation::Sockets;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tower::Layer as _;
use trust_controller::attestation::attestation_server::AttestationServer;
use trust_controller::trust::sealing_server::SealingServer;

use crate::attestation_service::AttestationService;
use crate::sealing_service::SealingService;
use crate::shared_tpm::SharedTpm;
use crate::tpm::Tpm;

/// Without a call for that long, it exits: serviced starts it again on the next connection.
const IDLE: Duration = Duration::from_secs(60);

/// Serves the API on the socket serviced passed, until SIGTERM, or until idle.
pub async fn run() -> anyhow::Result<()> {
    let tpm = Tpm::open().with_context(|| format!("opening {}", Tpm::DEVICE))?;
    let tpm = SharedTpm::new(tpm);
    let socket = Sockets::from_env()
        .and_then(|mut sockets| sockets.take("api"))
        .context("taking the api socket serviced passed")?;
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;
    let mut terminate = unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;

    tracing::info!("serving");
    let idle = Idle::default();
    let router = tonic::transport::Server::builder()
        .add_service(idle.layer(AttestationServer::new(AttestationService::new(tpm.clone()))))
        .add_service(idle.layer(SealingServer::new(SealingService::new(tpm))));
    libserviced::authorization::serve(router, socket, serviced, async move {
        tokio::select! {
            _ = terminate.recv() => tracing::info!("terminated"),
            () = idle.wait(IDLE) => tracing::info!("idle, exiting"),
        }
    })
    .await
    .context("serving")
}

//! The daemon serving the socket's APIs from the TPM.

use anyhow::Context as _;
use libserviced::activation::Sockets;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use trust_controller::attestation::attestation_server::AttestationServer;
use trust_controller::trust::sealing_server::SealingServer;

use crate::attestation_service::AttestationService;
use crate::sealing_service::SealingService;
use crate::shared_tpm::SharedTpm;
use crate::tpm::Tpm;

/// Serves the API on the socket serviced passed, until SIGTERM.
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
    let router = tonic::transport::Server::builder()
        .add_service(AttestationServer::new(AttestationService::new(tpm.clone())))
        .add_service(SealingServer::new(SealingService::new(tpm)));
    libserviced::authorization::serve(router, socket, serviced, async move {
        terminate.recv().await;
        tracing::info!("terminated");
    })
    .await
    .context("serving")
}

//! `storage-controller` without a command: the daemon serving its API.

use std::path::PathBuf;

use anyhow::Context as _;
use libserviced::activation::Sockets;
use storage_controller::storage::storage_controller_server::StorageControllerServer;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tracing::info;

use crate::state;
use crate::state::State;
use crate::storage_service::StorageService;

/// Serves the API on the socket serviced passed, until SIGTERM.
pub async fn run() -> anyhow::Result<()> {
    let socket = Sockets::from_env()
        .and_then(|mut sockets| sockets.take("api"))
        .context("taking the api socket serviced passed")?;
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;
    let state_path = PathBuf::from(state::PATH);
    let state = State::load(&state_path)?;
    let service = StorageService::new(state_path, state);
    // Before serving: callers wait in the backlog meanwhile.
    service.resume().await.context("/var cannot be set up")?;
    let mut terminate = unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;

    info!("serving");
    let router =
        tonic::transport::Server::builder().add_service(StorageControllerServer::new(service));
    libserviced::authorization::serve(router, socket, serviced, async move {
        terminate.recv().await;
        info!("terminated");
    })
    .await
    .context("serving")
}

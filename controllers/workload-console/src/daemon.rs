//! The daemon serving `Console` on the socket serviced passed.

use std::path::PathBuf;

use anyhow::Context as _;
use libserviced::activation::Sockets;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use workload_console::console::console_server::ConsoleServer;

use crate::console_service::ConsoleService;

const CTR: &str = "/usr/bin/ctr";

/// Serves until SIGTERM.
pub async fn run() -> anyhow::Result<()> {
    let socket = Sockets::from_env()
        .and_then(|mut sockets| sockets.take("api"))
        .context("taking the api socket serviced passed")?;
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;
    let mut terminate = unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;

    tracing::info!("serving");
    let router = tonic::transport::Server::builder()
        .add_service(ConsoleServer::new(ConsoleService::new(PathBuf::from(CTR))));
    libserviced::authorization::serve(router, socket, serviced, async move {
        terminate.recv().await;
        tracing::info!("terminated");
    })
    .await
    .context("serving")
}

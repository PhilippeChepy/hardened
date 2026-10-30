//! The daemon serving `Console` on the socket serviced passed.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use controllers_helpers::idle::Idle;
use libserviced::activation::Sockets;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tower::Layer as _;
use workload_console::console::console_server::ConsoleServer;

use crate::console_service::ConsoleService;

const CTR: &str = "/usr/bin/ctr";
/// Without a session for that long, it exits: serviced starts it again on the next connection.
const IDLE: Duration = Duration::from_secs(60);

/// Serves until SIGTERM, or until idle.
pub async fn run() -> anyhow::Result<()> {
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
        .add_service(idle.layer(ConsoleServer::new(ConsoleService::new(PathBuf::from(CTR)))));
    libserviced::authorization::serve(router, socket, serviced, async move {
        tokio::select! {
            _ = terminate.recv() => tracing::info!("terminated"),
            () = idle.wait(IDLE) => tracing::info!("idle, exiting"),
        }
    })
    .await
    .context("serving")
}

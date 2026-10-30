//! machine-apiproxy's life: the configuration kept by an earlier start served again, then the
//! configuration's socket until it is stopped.

use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use libserviced::activation::Sockets;
use machine_apiproxy::apiproxy::machine_api_proxy_server::MachineApiProxyServer;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tonic::transport::Server;

use crate::api_listener::ApiListener;
use crate::configuration_service::ConfigurationService;
use crate::state;

/// machine-controller's API, which authorized calls are forwarded to.
const UPSTREAM: &str = "/run/machine-controller/api.sock";

/// Runs machine-apiproxy until SIGTERM.
///
/// # Errors
///
/// When its socket was not passed, or the configuration's socket cannot be served.
pub async fn run() -> anyhow::Result<()> {
    let socket = Sockets::from_env()
        .and_then(|mut sockets| sockets.take("api"))
        .context("taking the configuration's socket")?;
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;
    let listener = Arc::new(ApiListener::new(PathBuf::from(UPSTREAM)));
    let path = Path::new(state::PATH);
    match state::load(path) {
        Ok(Some(config)) => {
            if let Err(e) = listener.apply(config).await {
                tracing::error!("cannot serve with the configuration kept: {e:#}");
            }
        }
        Ok(None) => {}
        Err(e) => tracing::warn!("ignoring the configuration kept: {e:#}"),
    }

    let mut terminate = unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let shutdown = async move {
        terminate.recv().await;
    };
    let configuration = ConfigurationService::new(listener.clone(), path.to_owned());
    let router = Server::builder().add_service(MachineApiProxyServer::new(configuration));
    libserviced::authorization::serve(router, socket, serviced, shutdown)
        .await
        .context("serving the configuration's socket")?;
    listener.stop().await;
    Ok(())
}

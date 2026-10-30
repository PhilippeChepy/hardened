//! The controller: serves its API and polls once configured.

use std::convert::Infallible;
use std::future;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use libserviced::activation::ActivatedSocket;
use libserviced::api::serviced_client::ServicedClient;
use time_controller::time::time_controller_server::TimeControllerServer;
use tonic::transport::Channel;
use tonic::transport::Server;

use crate::persisted_state::PersistedState;
use crate::poller;
use crate::time_service::TimeService;

/// Where time-controller keeps its configuration, in its runtime directory.
pub const STATE_FILE: &str = "/run/time-controller/state.json";

/// Serves `hardened.time.v1` on `api` to the callers `serviced` identifies, and keeps the clock
/// in sync with the configured servers, resuming with the configuration persisted in
/// `state_file`, if any. Returns only on an error.
pub async fn run(
    state_file: PathBuf,
    api: ActivatedSocket,
    serviced: ServicedClient<Channel>,
) -> anyhow::Result<Infallible> {
    let persisted = PersistedState::load(&state_file).unwrap_or_else(|error| {
        tracing::error!(error = format!("{error:#}"), "ignoring the persisted state");
        None
    });
    if persisted.is_some() {
        tracing::info!("resuming with the persisted configuration");
    }
    let service = Arc::new(TimeService::new(state_file, persisted));
    let router =
        Server::builder().add_service(TimeControllerServer::from_arc(Arc::clone(&service)));
    let serving = async {
        libserviced::authorization::serve(router, api, serviced, future::pending())
            .await
            .context("serving the API")?;
        Err(anyhow::anyhow!("the API stopped serving"))
    };
    tokio::select! {
        result = serving => result,
        never = poller::poll(service) => match never {},
    }
}

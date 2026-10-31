//! machine-controller's life: the setup and the controllers' configuration on its first start of
//! the boot, its state reloaded on a restart, then the machine's API, following DHCP's time
//! servers, until it is stopped.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use libserviced::activation::Sockets;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::notify;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::configuration;
use crate::controllers::Controllers;
use crate::dhcp_watch;
use crate::machine_api;
use crate::setup;
use crate::state;
use crate::state::State;

/// Runs machine-controller until SIGTERM.
///
/// # Errors
///
/// When its socket was not passed, network-controller or storage-controller cannot be
/// configured, or the API cannot be served.
pub async fn run() -> anyhow::Result<()> {
    let socket = Sockets::from_env()
        .and_then(|mut sockets| sockets.take("api"))
        .context("taking the API's socket")?;
    let controllers = Arc::new(Controllers::system());
    let path = Path::new(state::PATH);

    let kept = State::load(path).unwrap_or_else(|e| {
        warn!("ignoring the state of an earlier start: {e:#}");
        None
    });
    let mut state = match kept {
        Some(state) => {
            info!("restarted: the instance is set up and the controllers configured");
            state
        }
        None => {
            let setup = setup::run(&controllers).await;
            configuration::configure(
                &controllers,
                &setup.settings,
                &setup.identity.hostname,
                &setup.dhcp_time_servers,
            )
            .await?;
            let state = State {
                identity: setup.identity,
                settings: setup.settings,
                api_proxy_configured: false,
            };
            save(&state, path);
            state
        }
    };

    let router = machine_api::router(
        controllers.clone(),
        state.identity.clone(),
        state.settings.to_proto_without_secrets(),
    );
    let mut terminate = unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;
    let shutdown = async move {
        terminate.recv().await;
    };
    let serviced = ServicedClient::new(controllers.serviced.channel());
    let serving = tokio::spawn(libserviced::authorization::serve(
        router, socket, serviced, shutdown,
    ));
    if let Err(e) = notify::ready() {
        error!("cannot tell serviced machine-controller is ready: {e}");
    }
    info!("serving the machine's API");

    tokio::spawn(dhcp_watch::follow(
        controllers.clone(),
        state.settings.clone(),
    ));
    if !state.api_proxy_configured {
        configure_api_proxy(&controllers, &mut state, path).await;
    }
    serving
        .await
        .context("the API's task failed")?
        .context("serving the machine's API")
}

/// Enables and configures machine-apiproxy when the settings have the API, and keeps that it was.
async fn configure_api_proxy(controllers: &Controllers, state: &mut State, path: &Path) {
    let Some(config) = &state.settings.hardened.api else {
        return;
    };
    match configuration::configure_api_proxy(controllers, config).await {
        Ok(()) => {
            state.api_proxy_configured = true;
            save(state, path);
        }
        Err(e) => error!("cannot configure machine-apiproxy, the API is not served: {e:#}"),
    }
}

/// Keeps `state`; without it, a restart sets the instance up again.
fn save(state: &State, path: &Path) {
    if let Err(e) = state.save(path) {
        error!("cannot keep the state, a restart sets the instance up again: {e:#}");
    }
}

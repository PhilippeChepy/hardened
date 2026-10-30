//! `hardened.apiproxy.v1.MachineApiProxy`: machine-apiproxy's configuration, from
//! machine-controller.

use std::path::PathBuf;
use std::sync::Arc;

use machine_apiproxy::ApiConfig;
use machine_apiproxy::apiproxy;
use machine_apiproxy::apiproxy::machine_api_proxy_server::MachineApiProxy;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::api_listener::ApiListener;
use crate::state;

/// Keeps each configuration at `state`, then serves with it.
pub struct ConfigurationService {
    listener: Arc<ApiListener>,
    state: PathBuf,
}

impl ConfigurationService {
    /// Configures `listener`, keeping its configuration at `state`.
    #[must_use]
    pub fn new(listener: Arc<ApiListener>, state: PathBuf) -> Self {
        Self { listener, state }
    }
}

#[tonic::async_trait]
impl MachineApiProxy for ConfigurationService {
    async fn configure(
        &self,
        request: Request<apiproxy::Configuration>,
    ) -> Result<Response<()>, Status> {
        let config = ApiConfig::try_from(request.into_inner())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        state::save(&self.state, &config)
            .map_err(|e| Status::internal(format!("keeping the configuration: {e:#}")))?;
        self.listener
            .apply(config)
            .await
            .map_err(|e| Status::failed_precondition(format!("{e:#}")))?;
        Ok(Response::new(()))
    }
}

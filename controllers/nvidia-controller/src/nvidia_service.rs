//! `hardened.nvidia.v1.NvidiaController`: the state of the GPUs, as setting them up left it, and
//! their partitioning.

use std::sync::Arc;

use nvidia_controller::Mig;
use nvidia_controller::nvidia;
use nvidia_controller::nvidia::nvidia_controller_server::NvidiaController;
use tokio::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::partitioner::Partitioner;

/// Serves the state the setup left, partitioning the GPUs as configured.
pub struct NvidiaService {
    /// Locked while partitioning, one configuration at a time.
    state: Arc<Mutex<nvidia::State>>,
    partitioner: Partitioner,
}

impl NvidiaService {
    /// Serves `state`, partitioning with `partitioner`.
    #[must_use]
    pub fn new(state: nvidia::State, partitioner: Partitioner) -> Self {
        Self {
            state: Arc::new(Mutex::new(state)),
            partitioner,
        }
    }
}

#[tonic::async_trait]
impl NvidiaController for NvidiaService {
    async fn configure(
        &self,
        request: Request<nvidia::Configuration>,
    ) -> Result<Response<()>, Status> {
        let mig = (request.into_inner().mig)
            .map(Mig::try_from)
            .transpose()
            .map_err(Status::invalid_argument)?;
        let mut state = self.state.lock().await;
        if !state.ready {
            return Ok(Response::new(()));
        }
        let partitioner = self.partitioner.clone();
        let mut gpus = state.gpus.clone();
        let (gpus, outcome) = tokio::task::spawn_blocking(move || {
            let outcome = partitioner.apply(mig.as_ref(), &mut gpus);
            (gpus, outcome)
        })
        .await
        .map_err(|e| Status::internal(format!("partitioning: {e}")))?;
        state.gpus = gpus;
        state.reboot_required = outcome.reboot_required;
        state.error = (!outcome.errors.is_empty()).then(|| outcome.errors.join("; "));
        match &state.error {
            Some(error) => Err(Status::failed_precondition(error.clone())),
            None => Ok(Response::new(())),
        }
    }

    async fn get_state(&self, _: Request<()>) -> Result<Response<nvidia::State>, Status> {
        Ok(Response::new(self.state.lock().await.clone()))
    }
}

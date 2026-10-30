//! The TPM, shared by the services of the socket.

use std::sync::Arc;
use std::sync::Mutex;

use tonic::Status;

use crate::tpm::Tpm;

/// The TPM, one command at a time: the resource manager serializes them anyway, and the
/// attestation key is cached in the session.
#[derive(Clone)]
pub struct SharedTpm(Arc<Mutex<Tpm>>);

impl SharedTpm {
    /// Shares `tpm`.
    #[must_use]
    pub fn new(tpm: Tpm) -> Self {
        Self(Arc::new(Mutex::new(tpm)))
    }

    /// Runs `command` on the TPM, off the async runtime: TPM commands block.
    pub async fn run<T: Send + 'static>(
        &self,
        command: impl FnOnce(&mut Tpm) -> T + Send + 'static,
    ) -> Result<T, Status> {
        let tpm = self.0.clone();
        tokio::task::spawn_blocking(move || {
            // A command that panicked may have left the session mid-command: refuse to reuse it.
            let mut tpm = tpm
                .lock()
                .map_err(|_| Status::internal("a previous TPM command panicked"))?;
            Ok(command(&mut tpm))
        })
        .await
        .map_err(|e| Status::internal(e.to_string()))?
    }
}

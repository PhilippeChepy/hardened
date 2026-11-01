//! The `StorageController` service: `/var`, set up once per boot.

use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;
use libserviced::notify;
use storage_controller::Encryption;
use storage_controller::StorageSettings;
use storage_controller::storage;
use storage_controller::storage::storage_controller_server::StorageController;
use tokio::runtime::Handle;
use tokio::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::setup;
use crate::state::State;

/// Where the state is mounted.
const VAR: &str = "/var";

/// Serves the `StorageController` service, and sets `/var` up.
pub struct StorageService {
    state_path: PathBuf,
    /// Held while `/var` is set up, so that concurrent calls wait for it.
    state: Mutex<Option<State>>,
}

impl StorageService {
    /// A service keeping its state at `state_path`, which held `state`.
    #[must_use]
    pub fn new(state_path: PathBuf, state: Option<State>) -> Self {
        Self {
            state_path,
            state: Mutex::new(state),
        }
    }

    /// Carries on from the kept state: ready at once if `/var` is set up, else sets it up with
    /// the kept configuration, if any.
    pub async fn resume(&self) -> anyhow::Result<()> {
        let mut state = self.state.lock().await;
        match state.as_ref() {
            Some(State::SetUp { .. }) => {
                info!("/var was set up by a previous run");
                ready();
                Ok(())
            }
            Some(&State::Configured { encryption }) => {
                info!(?encryption, "setting /var up with the kept configuration");
                self.set_up(&mut state, encryption).await
            }
            None => Ok(()),
        }
    }

    /// Sets `/var` up with `encryption`, keeping the configuration first and then what backs
    /// it, then reports ready.
    async fn set_up(
        &self,
        state: &mut Option<State>,
        encryption: Encryption,
    ) -> anyhow::Result<()> {
        let configured = State::Configured { encryption };
        save(&configured, &self.state_path);
        *state = Some(configured);
        let runtime = Handle::current();
        let backing = tokio::task::spawn_blocking(move || setup::run(encryption, &runtime))
            .await
            .context("setting /var up panicked")??;
        let set_up = State::SetUp { backing };
        save(&set_up, &self.state_path);
        *state = Some(set_up);
        ready();
        Ok(())
    }
}

#[tonic::async_trait]
impl StorageController for StorageService {
    async fn configure(
        &self,
        request: Request<storage::Configuration>,
    ) -> Result<Response<()>, Status> {
        let settings = StorageSettings::try_from(request.into_inner())
            .map_err(|e| Status::invalid_argument(e.to_string()))?;
        let mut state = self.state.lock().await;
        if let Some(State::SetUp { backing }) = state.as_ref() {
            let current = backing.encryption();
            if current != settings.encryption {
                warn!(
                    ?current,
                    configured = ?settings.encryption,
                    "/var is set up: the new encryption takes effect at the next boot"
                );
            }
            return Ok(Response::new(()));
        }
        self.set_up(&mut state, settings.encryption)
            .await
            .map_err(|e| Status::internal(format!("{e:#}")))?;
        Ok(Response::new(()))
    }

    async fn get_state(&self, _: Request<()>) -> Result<Response<storage::State>, Status> {
        let backing = match self.state.lock().await.as_ref() {
            Some(State::SetUp { backing }) => backing.clone(),
            _ => return Err(Status::failed_precondition("/var is not set up yet")),
        };
        let usage = tokio::task::spawn_blocking(|| rustix::fs::statvfs(Path::new(VAR)))
            .await
            .map_err(|e| Status::internal(e.to_string()))?
            .map_err(|e| Status::internal(format!("reading the usage of {VAR}: {e}")))?;
        Ok(Response::new(storage::State {
            backing: Some(backing.into()),
            size_bytes: usage.f_blocks * usage.f_frsize,
            available_bytes: usage.f_bavail * usage.f_frsize,
        }))
    }
}

/// Keeps `state`. A failure only costs a restart its memory: `/var` is set up anyway.
fn save(state: &State, path: &Path) {
    if let Err(e) = state.save(path) {
        error!(error = format!("{e:#}"), "cannot keep the state");
    }
}

/// Tells serviced `/var` is set up, so the services requiring it start.
fn ready() {
    if let Err(e) = notify::ready() {
        error!(error = %e, "cannot notify serviced of the readiness");
    }
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::*;
    use crate::backing::Backing;

    fn configuration(encryption: storage::Encryption) -> Request<storage::Configuration> {
        Request::new(storage::Configuration {
            encryption: encryption.into(),
        })
    }

    #[tokio::test]
    async fn serves_the_state_once_set_up() {
        let dir = tempfile::tempdir().unwrap();
        let service = StorageService::new(dir.path().join("state.json"), None);
        let status = service.get_state(Request::new(())).await.unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition);
        let status = service
            .configure(configuration(storage::Encryption::Unspecified))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);

        let set_up = State::SetUp {
            backing: Backing::Plain {
                partition: "/dev/vda4".into(),
            },
        };
        let service = StorageService::new(dir.path().join("state.json"), Some(set_up.clone()));
        let state = service
            .get_state(Request::new(()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(
            state.backing,
            Some(storage::state::Backing::Plain(storage::state::Plain {
                partition: "/dev/vda4".into(),
            }))
        );
        assert!(state.size_bytes >= state.available_bytes);

        // A new encryption waits for the next boot.
        service
            .configure(configuration(storage::Encryption::Tpm))
            .await
            .unwrap();
        assert_eq!(*service.state.lock().await, Some(set_up));
    }
}

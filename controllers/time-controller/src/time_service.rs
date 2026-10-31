//! `hardened.time.v1.TimeController`, and the state it shares with the poller.

use std::path::PathBuf;

use time_controller::TimeConfig;
use time_controller::time;
use time_controller::time::time_controller_server::TimeController;
use tokio::sync::watch;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::clock;
use crate::measurement::Measurement;
use crate::persisted_state::PersistedState;
use crate::sync_status::SyncStatus;

/// The configuration and status, shared by the API and the poller, and the configuration's
/// persistence.
pub struct TimeService {
    /// `None` until configured; the poller restarts at every change.
    pub configs: watch::Sender<Option<TimeConfig>>,
    /// What the poller last did.
    pub status: watch::Sender<SyncStatus>,
    /// Where the configuration is persisted.
    state_file: PathBuf,
}

impl TimeService {
    /// Starts from `persisted`, if any, and persists in `state_file`.
    #[must_use]
    pub fn new(state_file: PathBuf, persisted: Option<PersistedState>) -> Self {
        Self {
            configs: watch::Sender::new(persisted.map(|persisted| persisted.config)),
            status: watch::Sender::new(SyncStatus::default()),
            state_file,
        }
    }

    /// Persists `config`, then has the poller use it (unless it already does).
    pub fn apply(&self, config: TimeConfig) -> anyhow::Result<()> {
        let persisted = PersistedState {
            config: config.clone(),
        };
        persisted.save(&self.state_file)?;
        self.configs.send_if_modified(|current| {
            let changed = current.as_ref() != Some(&config);
            *current = Some(config);
            changed
        });
        Ok(())
    }

    /// Records a round of the poller, which polls every `poll_seconds` from now on.
    pub fn record(&self, round: Result<Measurement, String>, poll_seconds: u32) {
        self.status.send_modify(|status| {
            status.poll_seconds = poll_seconds;
            match round {
                Ok(measurement) => {
                    status.last = Some(measurement);
                    status.error = None;
                }
                Err(error) => status.error = Some(error),
            }
        });
    }
}

#[tonic::async_trait]
impl TimeController for TimeService {
    async fn configure(
        &self,
        request: Request<time::Configuration>,
    ) -> Result<Response<()>, Status> {
        let config = TimeConfig::try_from(request.into_inner())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        if let Err(error) = self.apply(config) {
            tracing::error!(error = format!("{error:#}"), "persisting the configuration");
            return Err(Status::internal(format!("{error:#}")));
        }
        Ok(Response::new(()))
    }

    async fn get_status(&self, _: Request<()>) -> Result<Response<time::Status>, Status> {
        let clock = clock::state()
            .map_err(|error| Status::internal(format!("reading the clock: {error}")))?;
        let config = self.configs.borrow().clone();
        let status = self.status.borrow().to_message(config.as_ref(), clock);
        Ok(Response::new(status))
    }
}

#[cfg(test)]
mod tests {
    use controllers_helpers::NonEmpty;
    use time_controller::TimeOrigin;
    use time_controller::TimeSource;

    use super::*;
    use crate::measurement::tests::measurement;

    fn configuration(servers: &[&str], origin: time::Origin) -> Request<time::Configuration> {
        Request::new(time::Configuration {
            servers: servers.iter().map(|&s| s.to_owned()).collect(),
            origin: origin.into(),
            source: time::Source::Ntp.into(),
        })
    }

    async fn status(service: &TimeService) -> time::Status {
        service
            .get_status(Request::new(()))
            .await
            .unwrap()
            .into_inner()
    }

    #[tokio::test]
    async fn configures_persists_and_serves_the_status() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        let service = TimeService::new(path.clone(), None);
        let unconfigured = status(&service).await;
        assert!(unconfigured.servers.is_empty());
        assert!(unconfigured.clock.is_some(), "the kernel's clock, always");

        let mut configs = service.configs.subscribe();
        service
            .configure(configuration(&["time.example.com"], time::Origin::Settings))
            .await
            .unwrap();
        assert!(configs.has_changed().unwrap(), "the poller restarts");
        configs.mark_unchanged();
        let config = TimeConfig {
            servers: NonEmpty::new("time.example.com".parse().unwrap()),
            origin: TimeOrigin::Settings,
            source: TimeSource::Ntp,
        };
        let persisted = PersistedState::load(&path).unwrap().unwrap();
        assert_eq!(persisted.config, config);
        let configured = status(&service).await;
        assert_eq!(configured.servers, ["time.example.com"]);
        assert_eq!(configured.origin(), time::Origin::Settings);

        service
            .configure(configuration(&["time.example.com"], time::Origin::Settings))
            .await
            .unwrap();
        assert!(!configs.has_changed().unwrap(), "unchanged: no restart");

        service.record(Ok(measurement()), 32);
        assert_eq!(
            status(&service).await.last_correction,
            Some(time::Correction::from(&measurement()))
        );
        let persisted = PersistedState::load(&path).unwrap().unwrap();
        let restarted = TimeService::new(path, Some(persisted));
        assert_eq!(*restarted.configs.borrow(), Some(config));
        let resumed = status(&restarted).await;
        assert_eq!(resumed.last_correction, None, "it polls again");
    }

    #[tokio::test]
    async fn refuses_an_invalid_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let service = TimeService::new(dir.path().join("state.json"), None);
        for request in [
            configuration(&[], time::Origin::Default),
            configuration(&["ntp://x"], time::Origin::Default),
            configuration(&["time.example.com"], time::Origin::Unspecified),
        ] {
            let error = service.configure(request).await.unwrap_err();
            assert_eq!(error.code(), tonic::Code::InvalidArgument, "{error:?}");
        }
        assert_eq!(*service.configs.borrow(), None);
        assert!(!dir.path().join("state.json").exists());
    }
}

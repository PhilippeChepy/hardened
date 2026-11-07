//! `hardened.firewall.v1.FirewallController`: the configuration, applied through a
//! [`Backend`] (nf_tables, or a fake in tests) and persisted, and the status.
//!
//! The socket's allow-list names the services that may call; the methods changing the firewall
//! are, in addition, root's: a service whose processes run as several users (a login service's
//! sessions, in its cgroup) may only have its root processes change it, as serviced's `api-users`
//! does for its API.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex as SyncMutex;
use std::time::SystemTime;

use firewall_controller::FirewallConfig;
use firewall_controller::Ruleset;
use firewall_controller::Service;
use firewall_controller::drop_log::RecentBlocked;
use firewall_controller::firewall;
use firewall_controller::firewall::firewall_controller_server::FirewallController;
use firewall_controller::nftables::RuleInfo;
use firewall_controller::nftables::socket::NftError;
use firewall_controller::nftables::socket::NftSocket;
use firewall_controller::ruleset::text;
use libserviced::authorization::Caller;
use tokio::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::persisted_state::PersistedState;

/// What applies rulesets and reads the table back.
pub trait Backend: Send + Sync + 'static {
    /// Replaces the table by `ruleset`, or removes it; the generation after.
    fn apply(&self, ruleset: Option<&Ruleset>) -> Result<u32, NftError>;
    /// The table's rules; `None` without the table.
    fn rules(&self) -> Result<Option<Vec<RuleInfo>>, NftError>;
}

/// nf_tables, through a socket of its own for each call.
pub struct Nftables;

impl Backend for Nftables {
    fn apply(&self, ruleset: Option<&Ruleset>) -> Result<u32, NftError> {
        NftSocket::open()?.apply(ruleset)
    }

    fn rules(&self) -> Result<Option<Vec<RuleInfo>>, NftError> {
        let mut socket = NftSocket::open()?;
        if !socket.table_exists()? {
            return Ok(None);
        }
        socket.rules().map(Some)
    }
}

/// How the configuration's last application went.
#[derive(Debug, Clone)]
enum Applied {
    /// Not tried yet.
    Never,
    /// Applied at this time, nf_tables at this generation.
    Done(SystemTime, u32),
    /// Failed.
    Failed(String),
    /// The kernel has no nf_tables.
    Unavailable(String),
}

/// The configuration and its application.
struct State {
    config: FirewallConfig,
    applied: Applied,
    /// Why the persisted configuration was ignored at start, if it was.
    notice: Option<String>,
}

/// The configuration, applied with a [`Backend`], persisted in `state_file`.
pub struct FirewallService {
    /// Held across an application: one at a time.
    state: Mutex<State>,
    /// What `ResetConfig` sets, and what a refused kept configuration gives way to.
    default: FirewallConfig,
    state_file: PathBuf,
    backend: Arc<dyn Backend>,
    /// What the kernel's log says was blocked.
    recent: Arc<SyncMutex<RecentBlocked>>,
}

/// Fails with PERMISSION_DENIED unless `request` comes from a root process (see the module's
/// documentation). A request without a caller (not served through serviced's authorization:
/// tests) is let through.
fn require_root<T>(request: &Request<T>) -> Result<(), Status> {
    match Caller::of(request) {
        Some(caller) if caller.uid() != 0 => Err(Status::permission_denied(format!(
            "only root's processes of {} may change the firewall",
            caller.service()
        ))),
        Some(_) | None => Ok(()),
    }
}

/// The error of an application, as the API answers it.
fn apply_status(error: &NftError) -> Status {
    match error {
        NftError::Unavailable(_) => Status::failed_precondition(error.to_string()),
        NftError::Io(_) | NftError::Refused { .. } => Status::aborted(format!(
            "not applied, the previous configuration stays: {error}"
        )),
    }
}

impl FirewallService {
    /// Starts from `config` (the persisted one, or `default` with a `notice` saying why), not
    /// applied yet; persists in `state_file`; logged packets in `recent`.
    #[must_use]
    pub fn new(
        config: FirewallConfig,
        default: FirewallConfig,
        notice: Option<String>,
        state_file: PathBuf,
        backend: Arc<dyn Backend>,
        recent: Arc<SyncMutex<RecentBlocked>>,
    ) -> Self {
        Self {
            state: Mutex::new(State {
                config,
                applied: Applied::Never,
                notice,
            }),
            default,
            state_file,
            backend,
            recent,
        }
    }

    /// Runs `backend`'s blocking call on a blocking thread.
    async fn blocking<T: Send + 'static>(
        &self,
        call: impl FnOnce(&dyn Backend) -> Result<T, NftError> + Send + 'static,
    ) -> Result<T, NftError> {
        let backend = Arc::clone(&self.backend);
        tokio::task::spawn_blocking(move || call(&*backend))
            .await
            .unwrap_or_else(|error| Err(NftError::Io(std::io::Error::other(error.to_string()))))
    }

    /// Applies the configuration as it is (at start, and on `Reapply`), recording the outcome.
    pub async fn apply_current(&self) -> Result<(), NftError> {
        let mut state = self.state.lock().await;
        let ruleset = Ruleset::of(&state.config);
        let result = self
            .blocking(move |backend| backend.apply(ruleset.as_ref()))
            .await;
        state.applied = match &result {
            Ok(generation) => Applied::Done(SystemTime::now(), *generation),
            Err(error @ NftError::Unavailable(_)) => Applied::Unavailable(error.to_string()),
            Err(error) => Applied::Failed(error.to_string()),
        };
        result.map(|_| ())
    }

    /// The first application, before the network comes up, which fails closed: `Ok` when the
    /// network may come up, the configuration applied, or the kernel without nf_tables (nothing
    /// can be filtered: the status says so). A kept configuration the kernel refuses gives way to
    /// the default (not kept: the status says why); an error otherwise is returned, for the
    /// controller to exit and be restarted, the network waiting.
    pub async fn start(&self) -> Result<(), NftError> {
        match self.apply_current().await {
            Ok(()) | Err(NftError::Unavailable(_)) => return Ok(()),
            Err(error) => {
                let mut state = self.state.lock().await;
                if state.config == self.default {
                    return Err(error);
                }
                tracing::error!(%error, "the kept configuration is refused: the default applies");
                state.config = self.default.clone();
                state.notice = Some(format!(
                    "the kept configuration was refused, the default applies: {error}"
                ));
            }
        }
        self.apply_current().await
    }

    /// Applies `config`, then keeps it. When it cannot be applied, or kept, the previous one
    /// stays, applied and kept.
    async fn set(&self, config: FirewallConfig) -> Result<(), Status> {
        let mut state = self.state.lock().await;
        let ruleset = Ruleset::of(&config);
        let generation = self
            .blocking(move |backend| backend.apply(ruleset.as_ref()))
            .await
            .map_err(|error| {
                tracing::warn!(%error, "the configuration cannot be applied");
                apply_status(&error)
            })?;
        let persisted = PersistedState {
            config: config.clone(),
        };
        if let Err(error) = persisted.save(&self.state_file) {
            tracing::error!(error = format!("{error:#}"), "keeping the configuration");
            let previous = Ruleset::of(&state.config);
            if let Err(error) = self.blocking(move |b| b.apply(previous.as_ref())).await {
                tracing::error!(%error, "restoring the previous configuration");
                state.applied = Applied::Failed(error.to_string());
            }
            return Err(Status::internal(format!(
                "not kept, the previous configuration stays: {error:#}"
            )));
        }
        tracing::info!(
            enabled = config.enabled,
            generation,
            "configuration applied and kept"
        );
        state.config = config;
        state.applied = Applied::Done(SystemTime::now(), generation);
        state.notice = None;
        Ok(())
    }

    /// The status: the configuration, how its application went, what the table has.
    pub async fn status(&self) -> firewall::Status {
        let state = self.state.lock().await;
        let mut status = firewall::Status {
            config: Some((&state.config).into()),
            ..firewall::Status::default()
        };
        if let Applied::Done(at, generation) = state.applied {
            status.applied_at = Some(at.into());
            status.generation = generation;
        }
        let ruleset = Ruleset::of(&state.config);
        if let Some(ruleset) = &ruleset {
            status.ruleset = text::render(ruleset);
        }
        let mut error = state.notice.clone();
        let rules = match &state.applied {
            Applied::Unavailable(why) => {
                status.set_state(if state.config.enabled {
                    firewall::State::Unavailable
                } else {
                    firewall::State::Off
                });
                error = Some(why.clone());
                None
            }
            Applied::Failed(why) => {
                status.set_state(firewall::State::NotApplied);
                error = Some(why.clone());
                None
            }
            Applied::Never => {
                status.set_state(firewall::State::NotApplied);
                error = Some("not applied yet".to_owned());
                None
            }
            Applied::Done(..) if !state.config.enabled => {
                status.set_state(firewall::State::Off);
                None
            }
            Applied::Done(..) => match self.blocking(|backend| backend.rules()).await {
                Ok(Some(rules)) => {
                    status.set_state(firewall::State::Active);
                    Some(rules)
                }
                Ok(None) => {
                    status.set_state(firewall::State::NotApplied);
                    error = Some(
                        "the table inet firewall-controller is missing (flushed?): reapply the configuration"
                            .to_owned(),
                    );
                    None
                }
                Err(why) => {
                    status.set_state(firewall::State::Active);
                    error = Some(format!("reading the table: {why}"));
                    None
                }
            },
        };
        status.error = match (error, &state.notice) {
            (Some(error), Some(notice)) if error != *notice => Some(format!("{notice}; {error}")),
            (error, notice) => error.or_else(|| notice.clone()),
        };
        for rule in rules.unwrap_or_default() {
            if matches!(rule.comment.as_str(), "drop" | "reject") {
                status.blocked_packets = status.blocked_packets.saturating_add(rule.packets);
            }
            status.rules.push(firewall::Rule {
                chain: rule.chain,
                comment: rule.comment,
                packets: rule.packets,
                bytes: rule.bytes,
                handle: rule.handle,
            });
        }
        if let Ok(recent) = self.recent.lock() {
            status.recent_blocked = recent
                .list()
                .iter()
                .map(|blocked| firewall::Blocked {
                    outbound: blocked.kind.outbound,
                    interface: blocked.kind.interface.clone(),
                    protocol: blocked.kind.protocol.clone(),
                    source: blocked.kind.source.to_string(),
                    destination: blocked.kind.destination.to_string(),
                    port: blocked.kind.port.map(u32::from),
                    count: blocked.count,
                    last: Some(blocked.last.into()),
                })
                .collect();
        }
        status
    }
}

#[tonic::async_trait]
impl FirewallController for FirewallService {
    async fn get_status(&self, _: Request<()>) -> Result<Response<firewall::Status>, Status> {
        Ok(Response::new(self.status().await))
    }

    async fn set_config(
        &self,
        request: Request<firewall::Config>,
    ) -> Result<Response<firewall::Status>, Status> {
        require_root(&request)?;
        let config = FirewallConfig::try_from(request.into_inner())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        self.set(config).await?;
        Ok(Response::new(self.status().await))
    }

    async fn reset_config(
        &self,
        request: Request<()>,
    ) -> Result<Response<firewall::Status>, Status> {
        require_root(&request)?;
        self.set(self.default.clone()).await?;
        Ok(Response::new(self.status().await))
    }

    async fn reapply(&self, request: Request<()>) -> Result<Response<firewall::Status>, Status> {
        require_root(&request)?;
        self.apply_current()
            .await
            .map_err(|error| apply_status(&error))?;
        Ok(Response::new(self.status().await))
    }

    async fn list_services(
        &self,
        _: Request<()>,
    ) -> Result<Response<firewall::ServiceList>, Status> {
        Ok(Response::new(firewall::ServiceList {
            services: Service::all().map(Into::into).collect(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex as StdMutex;

    use firewall_controller::Inbound;

    use super::*;

    /// nf_tables as a table in memory; failing applications while `fail` is set.
    #[derive(Default)]
    struct Fake {
        table: StdMutex<Option<Ruleset>>,
        generation: StdMutex<u32>,
        fail: StdMutex<Option<fn() -> NftError>>,
        /// How many applications fail with `fail`; all of them when 0.
        fail_count: StdMutex<usize>,
    }

    impl Backend for Fake {
        fn apply(&self, ruleset: Option<&Ruleset>) -> Result<u32, NftError> {
            if let Some(error) = *self.fail.lock().unwrap() {
                let mut count = self.fail_count.lock().unwrap();
                match *count {
                    0 => return Err(error()),
                    1 => {
                        *count = usize::MAX;
                        return Err(error());
                    }
                    usize::MAX => {}
                    _ => {
                        *count -= 1;
                        return Err(error());
                    }
                }
            }
            *self.table.lock().unwrap() = ruleset.cloned();
            let mut generation = self.generation.lock().unwrap();
            *generation += 1;
            Ok(*generation)
        }

        fn rules(&self) -> Result<Option<Vec<RuleInfo>>, NftError> {
            Ok(self.table.lock().unwrap().as_ref().map(|ruleset| {
                ruleset
                    .rules()
                    .enumerate()
                    .map(|(i, (hook, rule))| RuleInfo {
                        chain: hook.name().to_owned(),
                        handle: i as u64 + 1,
                        comment: rule.comment.clone(),
                        packets: if rule.action.blocks() { 3 } else { 0 },
                        bytes: 0,
                    })
                    .collect()
            }))
        }
    }

    /// Starting from the firewall off.
    fn service(dir: &tempfile::TempDir, fake: Arc<Fake>) -> FirewallService {
        let off = FirewallConfig {
            enabled: false,
            ..FirewallConfig::default()
        };
        FirewallService::new(
            off,
            FirewallConfig::default(),
            None,
            dir.path().join("config.json"),
            fake,
            Arc::default(),
        )
    }

    fn enabled() -> firewall::Config {
        let config = FirewallConfig {
            inbound: Inbound::Reject,
            ..FirewallConfig::default()
        };
        (&config).into()
    }

    /// `message`, as a process of `uid` of an allowed service sends it.
    fn from<T>(uid: u32, message: T) -> Request<T> {
        let mut request = Request::new(message);
        request
            .extensions_mut()
            .insert(Caller::new("console".parse().unwrap(), 42, uid));
        request
    }

    #[tokio::test]
    async fn applies_keeps_and_reports() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::default());
        let service = service(&dir, Arc::clone(&fake));
        let status = service.status().await;
        assert_eq!(status.state(), firewall::State::NotApplied, "not yet");
        service.apply_current().await.unwrap();
        let status = service.status().await;
        assert_eq!(status.state(), firewall::State::Off);
        assert!(status.rules.is_empty() && status.ruleset.is_empty());
        assert!(fake.table.lock().unwrap().is_none());

        let status = service
            .set_config(from(0, enabled()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.state(), firewall::State::Active);
        assert_eq!(status.error, None);
        assert_eq!(status.generation, 2);
        assert!(
            status
                .ruleset
                .starts_with("table inet firewall-controller {\n")
        );
        assert_eq!(status.rules.last().unwrap().comment, "reject");
        assert_eq!(
            status.blocked_packets,
            2 * 3,
            "the reject rules, not invalid"
        );
        let kept = PersistedState::load(&dir.path().join("config.json"))
            .unwrap()
            .unwrap();
        assert!(kept.config.enabled);

        // Flushed behind its back: reported, then reapplied.
        *fake.table.lock().unwrap() = None;
        let status = service.status().await;
        assert_eq!(status.state(), firewall::State::NotApplied);
        assert!(status.error.unwrap().contains("missing"));
        service.reapply(from(0, ())).await.unwrap();
        assert_eq!(service.status().await.state(), firewall::State::Active);

        let services = service
            .list_services(from(1000, ()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(services.services[0].name, "ssh");
    }

    #[tokio::test]
    async fn a_failed_application_keeps_the_previous_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let fake = Arc::new(Fake::default());
        let service = service(&dir, Arc::clone(&fake));
        service.apply_current().await.unwrap();
        *fake.fail.lock().unwrap() = Some(|| NftError::Refused {
            what: "adding the rule".into(),
            error: std::io::Error::from_raw_os_error(95),
        });
        let error = service.set_config(from(0, enabled())).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::Aborted, "{error:?}");
        assert!(error.message().contains("adding the rule"), "{error:?}");
        let status = service.status().await;
        assert!(!status.config.as_ref().unwrap().enabled, "the previous one");
        assert_eq!(status.state(), firewall::State::Off);
        assert!(!dir.path().join("config.json").exists(), "not kept");

        *fake.fail.lock().unwrap() =
            Some(|| NftError::Unavailable(std::io::Error::from_raw_os_error(93)));
        let error = service.set_config(from(0, enabled())).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::FailedPrecondition, "{error:?}");
        service.apply_current().await.unwrap_err();
        let status = service.status().await;
        assert_eq!(
            status.state(),
            firewall::State::Off,
            "disabled: unavailable is off"
        );
    }

    #[tokio::test]
    async fn the_start_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let refused: fn() -> NftError = || NftError::Refused {
            what: "adding the rule".into(),
            error: std::io::Error::from_raw_os_error(95),
        };
        let start = |config: FirewallConfig, fail: Option<fn() -> NftError>, fails: usize| {
            let fake = Arc::new(Fake::default());
            *fake.fail.lock().unwrap() = fail;
            *fake.fail_count.lock().unwrap() = fails;
            let service = FirewallService::new(
                config,
                FirewallConfig::default(),
                None,
                dir.path().join("config.json"),
                Arc::clone(&fake) as Arc<dyn Backend>,
                Arc::default(),
            );
            (service, fake)
        };
        let kept = FirewallConfig {
            inbound: Inbound::Reject,
            ..FirewallConfig::default()
        };

        // A kept configuration refused: the default instead, said in the status.
        let (service, fake) = start(kept.clone(), Some(refused), 1);
        service.start().await.unwrap();
        assert!(fake.table.lock().unwrap().is_some());
        let status = service.status().await;
        assert_eq!(status.state(), firewall::State::Active);
        assert!(
            status
                .error
                .unwrap()
                .contains("the kept configuration was refused")
        );
        assert_eq!(
            FirewallConfig::try_from(status.config.unwrap()).unwrap(),
            FirewallConfig::default()
        );

        // The default refused too, or the socket failing: not ready, the network waits.
        let (service, _) = start(kept, Some(refused), 2);
        assert!(service.start().await.is_err());
        let (service, _) = start(FirewallConfig::default(), Some(refused), 1);
        assert!(service.start().await.is_err());
        let io: fn() -> NftError = || NftError::Io(std::io::Error::from_raw_os_error(110));
        let (service, _) = start(FirewallConfig::default(), Some(io), 1);
        assert!(service.start().await.is_err());

        // No nf_tables: ready, unavailable.
        let unavailable: fn() -> NftError =
            || NftError::Unavailable(std::io::Error::from_raw_os_error(93));
        let (service, _) = start(FirewallConfig::default(), Some(unavailable), 1);
        service.start().await.unwrap();
        assert_eq!(service.status().await.state(), firewall::State::Unavailable);
    }

    #[tokio::test]
    async fn changes_are_root_s_and_validated() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(&dir, Arc::new(Fake::default()));
        let error = service.set_config(from(1000, enabled())).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        let error = service.reset_config(from(1000, ())).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        let error = service.reapply(from(1000, ())).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::PermissionDenied);
        assert!(
            service.get_status(from(1000, ())).await.is_ok(),
            "reading is open"
        );

        let mut invalid = enabled();
        invalid.inbound = 7;
        let error = service.set_config(from(0, invalid)).await.unwrap_err();
        assert_eq!(error.code(), tonic::Code::InvalidArgument);
        assert_eq!(error.message(), "inbound: must be drop, reject or accept");
        assert!(!dir.path().join("config.json").exists());

        service.set_config(from(0, enabled())).await.unwrap();
        let status = service
            .reset_config(from(0, ()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(status.state(), firewall::State::Active, "on by default");
        assert_eq!(
            FirewallConfig::try_from(status.config.unwrap()).unwrap(),
            FirewallConfig::default()
        );
    }
}

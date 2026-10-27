//! The dust API (see `dust-proto`), served on a unix socket to `dust-api`.

use std::io::SeekFrom;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use dust_proto::v1::{
    self, ApplyWorkloadRequest, EventLogResponse, HashAlgorithm, ListWorkloadsResponse, LogChunk, LogEntry,
    LogsRequest, PcrValue, PcrsRequest, PcrsResponse, QuoteRequest, QuoteResponse, SettingsResponse, VersionResponse,
    WorkloadLogsRequest, WorkloadRef, WorkloadSource,
    attestation_server::{Attestation, AttestationServer},
    machine_server::{Machine as MachineService, MachineServer},
    workloads_server::{Workloads, WorkloadsServer},
};
use futures::StreamExt as _;
use futures::stream::{self, BoxStream};
use rustix::fs::{Gid, Mode};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
use tokio::net::UnixListener;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::{ReceiverStream, UnixListenerStream};
use tonic::{Request, Response, Status};

use crate::attestation::{self, HashAlg, Tpm, TpmError};
use crate::logging::LogRecord;
use crate::machine::{Machine, PowerRequest};
use crate::settings::{ContainerSettings, ImageWorkload, MountSettings, RestartPolicy};
use crate::types::{InvalidValue, WorkloadName};
use crate::workloads::{self, LogDecoder, Manager, Source, State};

/// How often a followed workload log is checked for new output.
const LOG_POLL_INTERVAL: Duration = Duration::from_millis(500);
const LOG_CHUNK: u64 = 64 << 10;
/// PCRs of PC Client TPMs.
const ALL_PCRS: std::ops::Range<u32> = 0..24;

/// Serves the API on `socket` until the process exits.
pub async fn serve(machine: Arc<Machine>, socket: &Path) -> anyhow::Result<()> {
    let listener = bind(socket)?;
    tracing::info!("serving the API on {}", socket.display());
    tonic::transport::Server::builder()
        .add_service(MachineServer::new(MachineApi(machine.clone())))
        .add_service(WorkloadsServer::new(WorkloadsApi(machine.clone())))
        .add_service(AttestationServer::new(AttestationApi(machine)))
        .serve_with_incoming(UnixListenerStream::new(listener))
        .await
        .context("serving the API")
}

/// Binds the socket, accessible to root and the `dust-api` group only.
fn bind(socket: &Path) -> anyhow::Result<UnixListener> {
    let dir = socket.parent().context("the socket path has no parent")?;
    let gid = Some(Gid::from_raw(crate::api::ID));
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    rustix::fs::chmod(dir, Mode::from_raw_mode(0o750))?;
    rustix::fs::chown(dir, None, gid)?;
    match std::fs::remove_file(socket) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            return Err(e).with_context(|| format!("removing the stale {}", socket.display()));
        }
        _ => {}
    }
    let listener = UnixListener::bind(socket).with_context(|| format!("binding {}", socket.display()))?;
    rustix::fs::chmod(socket, Mode::from_raw_mode(0o660))?;
    rustix::fs::chown(socket, None, gid)?;
    Ok(listener)
}

fn internal(e: impl std::fmt::Display) -> Status {
    Status::internal(e.to_string())
}

fn invalid(e: InvalidValue) -> Status {
    Status::invalid_argument(e.to_string())
}

fn workload_name(name: String) -> Result<WorkloadName, Status> {
    WorkloadName::try_from(name).map_err(invalid)
}

/// Maps a workload manager error to a gRPC status.
fn workload_status(e: anyhow::Error) -> Status {
    match e.downcast_ref::<workloads::Error>() {
        Some(workloads::Error::NotFound(_)) => Status::not_found(e.to_string()),
        Some(workloads::Error::ShuttingDown) => Status::unavailable(e.to_string()),
        None => Status::internal(format!("{e:#}")),
    }
}

struct MachineApi(Arc<Machine>);

#[tonic::async_trait]
impl MachineService for MachineApi {
    async fn version(&self, _: Request<()>) -> Result<Response<VersionResponse>, Status> {
        let info = &self.0.info;
        Ok(Response::new(VersionResponse {
            os_name: info.os_name.to_owned(),
            os_version: info.os_version.clone(),
            kernel: info.kernel.clone(),
            platform: info.platform.map(|p| p.to_string()).unwrap_or_default(),
            instance_id: info.instance_id.clone().unwrap_or_default(),
            hostname: info.hostname.to_string(),
            boot_id: info.boot_id.map(|id| id.to_string()).unwrap_or_default(),
            booted_at: Some(info.booted_at.into()),
        }))
    }

    type LogsStream = BoxStream<'static, Result<LogEntry, Status>>;

    async fn logs(&self, request: Request<LogsRequest>) -> Result<Response<Self::LogsStream>, Status> {
        let request = request.into_inner();
        let (past, live) = self.0.logs.snapshot(request.tail as usize);
        let past = stream::iter(past).map(|record| Ok(log_entry(record)));
        if !request.follow {
            return Ok(Response::new(past.boxed()));
        }
        let live = stream::unfold(live, |mut live| async move {
            loop {
                match live.recv().await {
                    Ok(record) => return Some((Ok(log_entry(record)), live)),
                    // A slow client misses entries rather than slowing dust-init down.
                    Err(broadcast::error::RecvError::Lagged(_)) => {}
                    Err(broadcast::error::RecvError::Closed) => return None,
                }
            }
        });
        Ok(Response::new(past.chain(live).boxed()))
    }

    async fn get_settings(&self, _: Request<()>) -> Result<Response<SettingsResponse>, Status> {
        // The private key serializes as `<redacted>`: settings are safe to expose.
        let mut settings = self.0.settings.clone();
        let api_workloads = match self.0.workloads.get() {
            Some(manager) => manager.list().await,
            None => Vec::new(),
        };
        for status in api_workloads {
            if status.source == Source::Api {
                let workload = status.definition;
                let container = ContainerSettings {
                    enabled: true,
                    workload,
                };
                settings.hardened.containers.insert(status.name, container);
            }
        }
        let toml = toml::to_string_pretty(&settings).map_err(internal)?;
        Ok(Response::new(SettingsResponse { toml }))
    }

    async fn reboot(&self, _: Request<()>) -> Result<Response<()>, Status> {
        self.power(PowerRequest::Reboot)
    }

    async fn shutdown(&self, _: Request<()>) -> Result<Response<()>, Status> {
        self.power(PowerRequest::PowerOff)
    }
}

impl MachineApi {
    fn power(&self, request: PowerRequest) -> Result<Response<()>, Status> {
        tracing::info!(?request, "power state change requested through the API");
        match self.0.power.try_send(request) {
            // Another request is already being handled.
            Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(Response::new(())),
            Err(mpsc::error::TrySendError::Closed(_)) => Err(Status::unavailable("power management is not available")),
        }
    }
}

fn log_entry(record: LogRecord) -> LogEntry {
    LogEntry {
        time: Some(record.time.into()),
        level: record.level.as_str().to_ascii_lowercase(),
        target: record.target,
        message: record.message,
    }
}

struct WorkloadsApi(Arc<Machine>);

#[tonic::async_trait]
impl Workloads for WorkloadsApi {
    async fn list(&self, _: Request<()>) -> Result<Response<ListWorkloadsResponse>, Status> {
        let workloads = self.manager()?.list().await.iter().map(workload).collect();
        Ok(Response::new(ListWorkloadsResponse { workloads }))
    }

    async fn apply(&self, request: Request<ApplyWorkloadRequest>) -> Result<Response<v1::Workload>, Status> {
        let ApplyWorkloadRequest { name, spec } = request.into_inner();
        let name = workload_name(name)?;
        let spec = image_workload(spec.ok_or_else(|| Status::invalid_argument("spec is required"))?)?;
        let manager = self.manager()?;
        self.ensure_api_owned(manager, &name, false)?;
        manager.apply(&name, spec, Source::Api).await.map_err(workload_status)?;
        tracing::info!("workload {name} applied through the API");
        let status = manager
            .status(&name)
            .ok_or_else(|| Status::aborted("workload removed concurrently"))?;
        Ok(Response::new(workload(&status)))
    }

    async fn remove(&self, request: Request<WorkloadRef>) -> Result<Response<()>, Status> {
        let name = workload_name(request.into_inner().name)?;
        let manager = self.manager()?;
        self.ensure_api_owned(manager, &name, true)?;
        manager.remove(&name).await.map_err(workload_status)?;
        Ok(Response::new(()))
    }

    async fn restart(&self, request: Request<WorkloadRef>) -> Result<Response<()>, Status> {
        let name = workload_name(request.into_inner().name)?;
        self.manager()?.restart(&name).await.map_err(workload_status)?;
        Ok(Response::new(()))
    }

    type LogsStream = BoxStream<'static, Result<LogChunk, Status>>;

    async fn logs(&self, request: Request<WorkloadLogsRequest>) -> Result<Response<Self::LogsStream>, Status> {
        let request = request.into_inner();
        let name = workload_name(request.name)?;
        // Read from the file, so the logs of earlier runs are there even without containerd.
        let path = workloads::log_path(Path::new(workloads::LOG_DIR), &name);
        let known = self.0.workloads.get().is_some_and(|m| m.status(&name).is_some());
        if !known && !tokio::fs::try_exists(&path).await.unwrap_or(false) {
            return Err(Status::not_found(format!("no workload named {name}")));
        }

        let (tx, rx) = mpsc::channel(4);
        tokio::spawn(async move {
            if let Err(e) = stream_log(&path, request.tail_bytes, request.follow, &tx).await {
                let status = Status::internal(format!("reading {}: {e}", path.display()));
                let _ = tx.send(Err(status)).await;
            }
        });
        Ok(Response::new(ReceiverStream::new(rx).boxed()))
    }
}

impl WorkloadsApi {
    fn manager(&self) -> Result<&Arc<Manager>, Status> {
        self.0.workloads.get().ok_or_else(|| {
            Status::unavailable("workloads are unavailable: containerd is not connected, or kubelet runs the pods")
        })
    }

    /// Refuses changes to workloads defined by user-data: the API only manages
    /// its own. `must_exist` also refuses unknown workloads.
    fn ensure_api_owned(&self, manager: &Manager, name: &WorkloadName, must_exist: bool) -> Result<(), Status> {
        match manager.source(name) {
            Some(Source::Api) => Ok(()),
            Some(Source::UserData) => Err(Status::failed_precondition(format!(
                "workload {name} is defined by user-data"
            ))),
            // A disabled user-data workload is not running, but still owns its name.
            None if self.0.settings.hardened.containers.contains_key(name) => Err(Status::failed_precondition(
                format!("workload {name} is defined by user-data"),
            )),
            None if must_exist => Err(Status::not_found(format!("no workload named {name}"))),
            None => Ok(()),
        }
    }
}

/// Streams the output of a workload, decoded from its CRI log: from the entries in the last
/// `tail` bytes of the log, then what is appended while `follow`ing, until the client goes away.
async fn stream_log(
    path: &Path,
    tail: u64,
    follow: bool,
    tx: &mpsc::Sender<Result<LogChunk, Status>>,
) -> std::io::Result<()> {
    let mut offset = match tokio::fs::metadata(path).await {
        Ok(metadata) if tail > 0 => metadata.len().saturating_sub(tail),
        _ => 0,
    };
    // Starting within the log, the first entry is truncated.
    let mut decoder = if offset > 0 {
        LogDecoder::mid_entry()
    } else {
        LogDecoder::default()
    };
    loop {
        loop {
            let raw = read_chunk(path, &mut offset).await?;
            if raw.is_empty() {
                break;
            }
            let data = decoder.decode(&raw);
            if data.is_empty() {
                continue;
            }
            if tx.send(Ok(LogChunk { data })).await.is_err() {
                return Ok(());
            }
        }
        if !follow {
            return Ok(());
        }
        tokio::select! {
            () = tx.closed() => return Ok(()),
            () = tokio::time::sleep(LOG_POLL_INTERVAL) => {}
        }
    }
}

/// Reads up to [`LOG_CHUNK`] bytes at `offset`, restarting from the beginning of a truncated
/// or rotated log. A missing log reads as empty.
async fn read_chunk(path: &Path, offset: &mut u64) -> std::io::Result<Vec<u8>> {
    let mut file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    if file.metadata().await?.len() < *offset {
        *offset = 0;
    }
    file.seek(SeekFrom::Start(*offset)).await?;
    let mut data = Vec::new();
    file.take(LOG_CHUNK).read_to_end(&mut data).await?;
    *offset += data.len() as u64;
    Ok(data)
}

/// Parses an API workload spec: the same types as user-data, so the same rules.
fn image_workload(spec: v1::WorkloadSpec) -> Result<ImageWorkload, Status> {
    let restart = match v1::RestartPolicy::try_from(spec.restart) {
        Ok(v1::RestartPolicy::Unspecified | v1::RestartPolicy::Always) => RestartPolicy::Always,
        Ok(v1::RestartPolicy::OnFailure) => RestartPolicy::OnFailure,
        Ok(v1::RestartPolicy::Never) => RestartPolicy::Never,
        Err(_) => {
            return Err(Status::invalid_argument(format!(
                "unknown restart policy {}",
                spec.restart
            )));
        }
    };
    let workload = ImageWorkload {
        image: spec.image.try_into().map_err(invalid)?,
        command: spec.command,
        args: spec.args,
        env: spec
            .env
            .into_iter()
            .map(|(name, value)| Ok((name.try_into().map_err(invalid)?, value)))
            .collect::<Result<_, Status>>()?,
        privileged: spec.privileged,
        restart,
        mounts: spec
            .mounts
            .into_iter()
            .map(|mount| {
                Ok(MountSettings {
                    source: mount.source.try_into().map_err(invalid)?,
                    destination: mount.destination.try_into().map_err(invalid)?,
                    read_only: mount.read_only,
                })
            })
            .collect::<Result<_, Status>>()?,
        console: false,
    };
    workload.check_arguments().map_err(invalid)?;
    Ok(workload)
}

fn workload_spec(container: &ImageWorkload) -> v1::WorkloadSpec {
    v1::WorkloadSpec {
        image: container.image.to_string(),
        command: container.command.clone(),
        args: container.args.clone(),
        env: container.env.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        privileged: container.privileged,
        restart: match container.restart {
            RestartPolicy::Always => v1::RestartPolicy::Always,
            RestartPolicy::OnFailure => v1::RestartPolicy::OnFailure,
            RestartPolicy::Never => v1::RestartPolicy::Never,
        }
        .into(),
        mounts: container
            .mounts
            .iter()
            .map(|mount| v1::Mount {
                source: mount.source.to_string(),
                destination: mount.destination.to_string(),
                read_only: mount.read_only,
            })
            .collect(),
    }
}

fn workload(status: &workloads::Status) -> v1::Workload {
    use v1::workload::{Exited, Failed, Pending, Pulling, Running, State as Wire};
    let state = match &status.state {
        State::Pending => Wire::Pending(Pending {}),
        State::Pulling => Wire::Pulling(Pulling {}),
        // The wire format has no "unknown": 0 is never a container's pid.
        State::Running { pid } => Wire::Running(Running { pid: pid.unwrap_or(0) }),
        State::Exited { code } => Wire::Exited(Exited { exit_code: *code }),
        State::Failed { reason } => Wire::Failed(Failed { reason: reason.clone() }),
    };
    v1::Workload {
        name: status.name.to_string(),
        spec: Some(workload_spec(&status.definition)),
        source: match status.source {
            Source::UserData => WorkloadSource::UserData,
            Source::Api => WorkloadSource::Api,
        }
        .into(),
        restarts: status.restarts,
        state: Some(state),
    }
}

struct AttestationApi(Arc<Machine>);

#[tonic::async_trait]
impl Attestation for AttestationApi {
    async fn pcrs(&self, request: Request<PcrsRequest>) -> Result<Response<PcrsResponse>, Status> {
        let request = request.into_inner();
        let bank = hash_alg(request.bank)?;
        let pcrs = pcr_selection(request.pcrs);
        let values = self.with_tpm(move |tpm| tpm.pcr_read(bank, &pcrs)).await?;
        Ok(Response::new(PcrsResponse {
            bank: hash_algorithm(bank).into(),
            values: pcr_values(values),
        }))
    }

    async fn event_log(&self, _: Request<()>) -> Result<Response<EventLogResponse>, Status> {
        let event_log = tokio::task::spawn_blocking(attestation::event_log)
            .await
            .map_err(internal)?
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => Status::failed_precondition("this machine has no TPM event log"),
                _ => Status::internal(format!("reading {}: {e}", attestation::EVENT_LOG)),
            })?;
        Ok(Response::new(EventLogResponse { event_log }))
    }

    async fn quote(&self, request: Request<QuoteRequest>) -> Result<Response<QuoteResponse>, Status> {
        let request = request.into_inner();
        let bank = hash_alg(request.bank)?;
        let pcrs = pcr_selection(request.pcrs);
        let nonce = request.nonce;
        let quote = self.with_tpm(move |tpm| tpm.quote(&nonce, bank, &pcrs)).await?;
        Ok(Response::new(QuoteResponse {
            attest: quote.attest,
            signature: quote.signature,
            ak_public: quote.ak_public,
            values: pcr_values(quote.pcrs),
        }))
    }
}

impl AttestationApi {
    /// Runs `f` on the TPM, off the async runtime.
    async fn with_tpm<T: Send + 'static>(
        &self,
        f: impl FnOnce(&mut Tpm) -> Result<T, TpmError> + Send + 'static,
    ) -> Result<T, Status> {
        let tpm = self
            .0
            .tpm
            .clone()
            .ok_or_else(|| Status::failed_precondition("this machine has no TPM"))?;
        tokio::task::spawn_blocking(move || f(&mut tpm.lock().unwrap_or_else(|e| e.into_inner())))
            .await
            .map_err(internal)?
            .map_err(tpm_status)
    }
}

fn tpm_status(e: TpmError) -> Status {
    let message = e.to_string();
    match e {
        TpmError::InvalidPcr(_) | TpmError::NoPcrSelected | TpmError::NonceTooLong(_) => {
            Status::invalid_argument(message)
        }
        TpmError::PcrUnavailable { .. } => Status::failed_precondition(message),
        TpmError::PcrsChanged => Status::aborted(message),
        TpmError::Io(_) | TpmError::Response(_) | TpmError::Malformed(_) | TpmError::QuoteMismatch(_) => {
            Status::internal(message)
        }
    }
}

fn hash_alg(bank: i32) -> Result<HashAlg, Status> {
    match HashAlgorithm::try_from(bank) {
        Ok(HashAlgorithm::Unspecified | HashAlgorithm::Sha256) => Ok(HashAlg::Sha256),
        Ok(HashAlgorithm::Sha1) => Ok(HashAlg::Sha1),
        Ok(HashAlgorithm::Sha384) => Ok(HashAlg::Sha384),
        Err(_) => Err(Status::invalid_argument(format!("unknown hash algorithm {bank}"))),
    }
}

fn hash_algorithm(bank: HashAlg) -> HashAlgorithm {
    match bank {
        HashAlg::Sha1 => HashAlgorithm::Sha1,
        HashAlg::Sha256 => HashAlgorithm::Sha256,
        HashAlg::Sha384 => HashAlgorithm::Sha384,
    }
}

fn pcr_selection(pcrs: Vec<u32>) -> Vec<u32> {
    if pcrs.is_empty() { ALL_PCRS.collect() } else { pcrs }
}

fn pcr_values(values: Vec<(u32, Vec<u8>)>) -> Vec<PcrValue> {
    values
        .into_iter()
        .map(|(index, digest)| PcrValue { index, digest })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> v1::WorkloadSpec {
        v1::WorkloadSpec {
            image: "docker.io/library/nginx:1.29".into(),
            command: vec!["nginx".into()],
            args: vec!["-g".into(), "daemon off;".into()],
            env: [("A".to_owned(), "1".to_owned())].into(),
            privileged: true,
            restart: v1::RestartPolicy::OnFailure.into(),
            mounts: vec![v1::Mount {
                source: "/var/lib/web".into(),
                destination: "/data".into(),
                read_only: true,
            }],
        }
    }

    #[test]
    fn workload_specs_round_trip() {
        let workload = image_workload(spec()).unwrap();
        assert!(!workload.console);
        assert_eq!(workload.restart, RestartPolicy::OnFailure);
        assert_eq!(workload.env["A"], "1");
        assert_eq!(workload.mounts[0].source.as_str(), "/var/lib/web");
        assert_eq!(workload_spec(&workload), spec());
    }

    #[test]
    fn restart_policy_defaults_to_always() {
        let mut unspecified = spec();
        unspecified.restart = v1::RestartPolicy::Unspecified.into();
        assert_eq!(image_workload(unspecified).unwrap().restart, RestartPolicy::Always);

        let mut unknown = spec();
        unknown.restart = 42;
        let status = image_workload(unknown).unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn rejects_invalid_specs_like_user_data() {
        assert!(workload_name("Web".into()).is_err());
        let invalid = [
            v1::WorkloadSpec {
                image: String::new(),
                ..spec()
            },
            v1::WorkloadSpec {
                mounts: vec![v1::Mount {
                    source: "/etc".into(),
                    destination: "/d".into(),
                    read_only: false,
                }],
                ..spec()
            },
            v1::WorkloadSpec {
                env: [("A=B".to_owned(), "1".to_owned())].into(),
                ..spec()
            },
            v1::WorkloadSpec {
                args: vec!["a\0b".into()],
                ..spec()
            },
        ];
        for spec in invalid {
            assert_eq!(image_workload(spec).unwrap_err().code(), tonic::Code::InvalidArgument);
        }
    }

    #[test]
    fn statuses_map_to_workloads() {
        let status = workloads::Status {
            name: "web".parse().unwrap(),
            definition: image_workload(spec()).unwrap(),
            source: Source::Api,
            state: State::Running { pid: Some(42) },
            restarts: 1,
        };
        let workload = workload(&status);
        assert_eq!(workload.source, i32::from(WorkloadSource::Api));
        assert_eq!(
            workload.state,
            Some(v1::workload::State::Running(v1::workload::Running { pid: 42 }))
        );
        assert_eq!(workload.spec.unwrap(), spec());

        let unknown_pid = workloads::Status {
            state: State::Running { pid: None },
            ..status
        };
        assert_eq!(
            super::workload(&unknown_pid).state,
            Some(v1::workload::State::Running(v1::workload::Running { pid: 0 }))
        );
    }

    #[test]
    fn maps_tpm_errors() {
        assert_eq!(
            tpm_status(TpmError::InvalidPcr(24)).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            tpm_status(TpmError::NonceTooLong(65)).code(),
            tonic::Code::InvalidArgument
        );
        assert_eq!(
            tpm_status(TpmError::PcrUnavailable {
                bank: HashAlg::Sha1,
                pcr: 0
            })
            .code(),
            tonic::Code::FailedPrecondition
        );
        assert_eq!(tpm_status(TpmError::Malformed("x")).code(), tonic::Code::Internal);
    }

    #[test]
    fn hash_algorithms_default_to_sha256() {
        assert_eq!(hash_alg(0).unwrap(), HashAlg::Sha256);
        assert_eq!(hash_alg(1).unwrap(), HashAlg::Sha1);
        assert_eq!(hash_alg(3).unwrap(), HashAlg::Sha384);
        assert!(hash_alg(9).is_err());
        assert_eq!(pcr_selection(Vec::new()).len(), 24);
        assert_eq!(pcr_selection(vec![7]), [7]);
    }

    #[test]
    fn maps_workload_errors() {
        let not_found = anyhow::Error::from(workloads::Error::NotFound("x".parse().unwrap()));
        assert_eq!(workload_status(not_found).code(), tonic::Code::NotFound);
        let other = anyhow::anyhow!("boom").context("applying");
        let status = workload_status(other);
        assert_eq!(status.code(), tonic::Code::Internal);
        assert_eq!(status.message(), "applying: boom");
    }

    #[tokio::test]
    async fn streams_decoded_workload_logs() {
        let entry = |tag: &str, message: &str| format!("2026-10-25T10:00:00.000000001Z stdout {tag} {message}\n");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.log");
        let second = entry("F", "second");
        tokio::fs::write(&path, [entry("F", "first"), second.clone()].concat())
            .await
            .unwrap();

        // The tail starts within the first entry, which is skipped.
        let (tx, mut rx) = mpsc::channel(4);
        stream_log(&path, second.len() as u64 + 3, false, &tx).await.unwrap();
        drop(tx);
        assert_eq!(rx.recv().await.unwrap().unwrap().data, b"second\n");
        assert!(rx.recv().await.is_none());

        let (tx, mut rx) = mpsc::channel(4);
        let follower = tokio::spawn({
            let path = path.clone();
            async move { stream_log(&path, 0, true, &tx).await }
        });
        assert_eq!(rx.recv().await.unwrap().unwrap().data, b"first\nsecond\n");
        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        std::io::Write::write_all(&mut file, [entry("P", "thi"), entry("F", "rd")].concat().as_bytes()).unwrap();
        assert_eq!(rx.recv().await.unwrap().unwrap().data, b"third\n");
        drop(rx);
        follower.await.unwrap().unwrap();

        let mut offset = 0;
        let missing = dir.path().join("missing.log");
        assert!(read_chunk(&missing, &mut offset).await.unwrap().is_empty());
    }
}

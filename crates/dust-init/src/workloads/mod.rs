//! Workloads run through containerd's CRI plugin (Kubernetes' `runtime.v1`).
//!
//! Each workload runs in its own pod sandbox and is driven by its own supervision task: make
//! sure the image is present (pulling it if needed), run the sandbox, create and start the
//! container, wait for it to exit and apply the restart policy. The runtime builds the OCI spec.
//! The images bundled in the root filesystem (the pod sandbox's) are imported at boot
//! ([`bundled`]).

mod bundled;
mod cri;
mod events;
mod logs;
mod pod;
mod supervisor;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;

use crate::settings::ImageWorkload;
use crate::types::{ContainerPath, WorkloadName};
use cri::Cri;
use events::Exits;
use supervisor::{Handle, Runtime, SharedRuntime};

pub use bundled::DIR as BUNDLED_IMAGES;
pub use logs::Decoder as LogDecoder;

/// Grace period given to a workload replaced, removed or restarted through [`Manager`].
const STOP_GRACE: Duration = Duration::from_secs(10);
/// Pod log directories, one per workload.
pub const LOG_DIR: &str = "/var/log/pods";
/// API workloads, persisted across reboots, in the state directory.
const PERSISTED: &str = "workloads.toml";

/// The log of workload `name` under `log_dir`, in the CRI format (see [`LogDecoder`]). It
/// outlives the workload and is readable without containerd.
pub fn log_path(log_dir: &Path, name: &WorkloadName) -> PathBuf {
    log_dir.join(name.as_str()).join(pod::log_file(name))
}

/// Where a workload definition comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    UserData,
    /// Applied through the API; persisted across reboots.
    Api,
}

crate::types::validated_string!(
    /// Absolute, normalized host path.
    HostPath,
    "host path",
    |path| {
        let normalized = path == "/"
            || path
                .strip_prefix('/')
                .is_some_and(|rest| rest.split('/').all(|segment| !matches!(segment, "" | "." | "..")));
        if normalized && !path.contains('\0') {
            Ok(())
        } else {
            Err("must be absolute and normalized (no '.', '..' or '//')")
        }
    }
);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindMount {
    pub source: HostPath,
    pub destination: ContainerPath,
    pub read_only: bool,
}

/// Lifecycle state of a workload, with the data only meaningful in that state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// Preparing (or waiting to restart).
    Pending,
    Pulling,
    Running {
        /// Host pid of the container's process, if the runtime reported it.
        pid: Option<u32>,
    },
    Exited {
        code: i32,
    },
    /// Could not be started; retried with backoff.
    Failed {
        reason: String,
    },
}

/// Observed state of a workload.
#[derive(Debug, Clone)]
pub struct Status {
    pub name: WorkloadName,
    pub definition: ImageWorkload,
    pub source: Source,
    pub state: State,
    pub restarts: u32,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("no workload named {0}")]
    NotFound(WorkloadName),
    #[error("workloads are shutting down")]
    ShuttingDown,
}

struct Workload {
    definition: ImageWorkload,
    source: Source,
    runtime: SharedRuntime,
    /// `None` while being stopped.
    supervisor: Option<Handle>,
}

pub struct Manager {
    cri: Cri,
    exits: Exits,
    state_dir: PathBuf,
    /// Pod log directories, one per workload.
    log_dir: PathBuf,
    workloads: Mutex<BTreeMap<WorkloadName, Workload>>,
    /// Serializes changes, which wait for workloads to stop.
    changes: tokio::sync::Mutex<()>,
    shutting_down: AtomicBool,
}

impl Manager {
    /// Connects to containerd (retrying until `timeout`, until its CRI runtime is ready),
    /// imports the bundled images of `images_dir`, removes the pods left by a previous boot and
    /// prepares the state directories.
    pub async fn connect(
        socket: &Path,
        state_dir: &Path,
        log_dir: &Path,
        images_dir: &Path,
        timeout: Duration,
    ) -> anyhow::Result<Arc<Self>> {
        for dir in [state_dir, log_dir] {
            tokio::fs::create_dir_all(dir)
                .await
                .with_context(|| format!("creating {}", dir.display()))?;
        }
        let (cri, channel, version) = Cri::connect(socket, timeout).await?;
        tracing::info!(
            "connected to {} {} (CRI {})",
            version.runtime_name,
            version.runtime_version,
            version.runtime_api_version
        );

        for path in bundled::archives(images_dir).await? {
            let archive = bundled::Archive::read(&path).await?;
            let reference = archive.image.reference.clone();
            let imported = bundled::import(&channel, &cri, archive)
                .await
                .with_context(|| format!("importing {} from {}", reference, path.display()))?;
            match imported {
                bundled::Imported::Imported => tracing::info!("imported bundled image {reference}"),
                bundled::Imported::AlreadyPresent => tracing::info!("bundled image {reference} already imported"),
            }
        }

        // Nothing runs yet: any workload pod is a leftover.
        let leftovers = cri
            .sandboxes(Default::default())
            .await
            .context("listing pod sandboxes")?
            .into_iter()
            .filter(|(_, labels)| labels.contains_key(pod::WORKLOAD_LABEL));
        for (sandbox, labels) in leftovers {
            tracing::info!(
                "removing the pod of workload {} left by a previous boot",
                labels[pod::WORKLOAD_LABEL]
            );
            if let Err(status) = cri.remove_sandbox(&sandbox).await {
                tracing::warn!("removing pod sandbox {sandbox}: {status}");
            }
        }

        let exits = Exits::spawn(cri.clone());
        Ok(Arc::new(Self {
            cri,
            exits,
            state_dir: state_dir.to_owned(),
            log_dir: log_dir.to_owned(),
            workloads: Mutex::default(),
            changes: tokio::sync::Mutex::default(),
            shutting_down: AtomicBool::new(false),
        }))
    }

    /// Starts or replaces a workload.
    pub async fn apply(
        self: &Arc<Self>,
        name: &WorkloadName,
        definition: ImageWorkload,
        source: Source,
    ) -> anyhow::Result<()> {
        let _changes = self.changes.lock().await;
        self.ensure_running()?;

        if source == Source::Api {
            self.persist(name, Some(&definition)).await?;
        } else if self.source(name) == Some(Source::Api) {
            self.persist(name, None).await?;
        }

        if let Some((handle, _)) = self.take_supervisor(name) {
            tracing::info!("workload {name} replaced");
            handle.stop(STOP_GRACE).await;
        }
        self.start(name, definition, source, 0);
        Ok(())
    }

    /// Starts the workloads previously applied through the API.
    pub async fn load_persisted(self: &Arc<Self>) -> anyhow::Result<()> {
        let persisted = self.read_persisted().await?;
        for (name, workload) in persisted {
            if let Some(source) = self.source(&name) {
                tracing::warn!("workload {name}: ignoring its API definition, {source:?} defines it");
                continue;
            }
            if let Err(e) = self.apply(&name, workload, Source::Api).await {
                tracing::warn!("workload {name}: {e:#}");
            }
        }
        Ok(())
    }

    /// Stops and forgets a workload.
    pub async fn remove(&self, name: &WorkloadName) -> anyhow::Result<()> {
        let _changes = self.changes.lock().await;
        self.ensure_running()?;
        let source = self.source(name).ok_or_else(|| Error::NotFound(name.clone()))?;
        if source == Source::Api {
            self.persist(name, None).await?;
        }
        if let Some((handle, _)) = self.take_supervisor(name) {
            handle.stop(STOP_GRACE).await;
        }
        self.lock().remove(name);
        tracing::info!("workload {name} removed");
        Ok(())
    }

    /// Stops a workload and starts it again.
    pub async fn restart(&self, name: &WorkloadName) -> anyhow::Result<()> {
        let _changes = self.changes.lock().await;
        self.ensure_running()?;
        let (definition, source) = {
            let workloads = self.lock();
            let workload = workloads.get(name).ok_or_else(|| Error::NotFound(name.clone()))?;
            (workload.definition.clone(), workload.source)
        };
        let restarts = match self.take_supervisor(name) {
            Some((handle, restarts)) => {
                handle.stop(STOP_GRACE).await;
                restarts
            }
            None => self.status(name).map_or(0, |s| s.restarts),
        };
        tracing::info!("workload {name} restarting");
        self.start(name, definition, source, restarts + 1);
        Ok(())
    }

    pub async fn list(&self) -> Vec<Status> {
        self.lock()
            .iter()
            .map(|(name, workload)| status(name, workload))
            .collect()
    }

    pub fn status(&self, name: &WorkloadName) -> Option<Status> {
        self.lock().get(name).map(|workload| status(name, workload))
    }

    /// Where a workload is defined, if it exists.
    pub fn source(&self, name: &WorkloadName) -> Option<Source> {
        self.lock().get(name).map(|workload| workload.source)
    }

    fn pod_log_dir(&self, name: &WorkloadName) -> PathBuf {
        self.log_dir.join(name.as_str())
    }

    /// Stops every workload: the stop signal, then SIGKILL after `grace`.
    pub async fn shutdown(&self, grace: Duration) {
        self.shutting_down.store(true, Ordering::SeqCst);
        let _changes = self.changes.lock().await;
        let handles: Vec<Handle> = self
            .lock()
            .values_mut()
            .filter_map(|workload| workload.supervisor.take())
            .collect();
        tracing::info!("stopping {} workloads", handles.len());
        futures::future::join_all(handles.into_iter().map(|handle| handle.stop(grace))).await;
    }

    fn start(&self, name: &WorkloadName, definition: ImageWorkload, source: Source, restarts: u32) {
        let runtime = Arc::new(Mutex::new(Runtime {
            state: State::Pending,
            restarts,
        }));
        let supervisor = Handle::spawn(supervisor::Context {
            name: name.clone(),
            definition: definition.clone(),
            cri: self.cri.clone(),
            exits: self.exits.clone(),
            log_directory: self.pod_log_dir(name),
            runtime: runtime.clone(),
        });
        let workload = Workload {
            definition,
            source,
            runtime,
            supervisor: Some(supervisor),
        };
        self.lock().insert(name.clone(), workload);
    }

    /// Takes the supervisor of a workload, leaving it listed while it stops, with its restart
    /// count.
    fn take_supervisor(&self, name: &WorkloadName) -> Option<(Handle, u32)> {
        let mut workloads = self.lock();
        let workload = workloads.get_mut(name)?;
        let restarts = workload.runtime.lock().unwrap_or_else(|e| e.into_inner()).restarts;
        Some((workload.supervisor.take()?, restarts))
    }

    fn ensure_running(&self) -> Result<(), Error> {
        if self.shutting_down.load(Ordering::SeqCst) {
            return Err(Error::ShuttingDown);
        }
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, BTreeMap<WorkloadName, Workload>> {
        self.workloads.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn persisted_path(&self) -> PathBuf {
        self.state_dir.join(PERSISTED)
    }

    async fn read_persisted(&self) -> anyhow::Result<BTreeMap<WorkloadName, ImageWorkload>> {
        read_persisted(&self.persisted_path()).await
    }

    /// Records (`Some`) or forgets (`None`) an API workload in the persisted definitions.
    async fn persist(&self, name: &WorkloadName, workload: Option<&ImageWorkload>) -> anyhow::Result<()> {
        let path = self.persisted_path();
        let mut persisted = read_persisted(&path).await?;
        match workload {
            Some(workload) => persisted.insert(name.clone(), workload.clone()),
            None => persisted.remove(name),
        };
        let text = toml::to_string_pretty(&persisted)?;
        tokio::task::spawn_blocking(move || write_atomic(&path, text.as_bytes()))
            .await?
            .context("persisting the API workloads")
    }
}

fn status(name: &WorkloadName, workload: &Workload) -> Status {
    let runtime = workload.runtime.lock().unwrap_or_else(|e| e.into_inner()).clone();
    Status {
        name: name.clone(),
        definition: workload.definition.clone(),
        source: workload.source,
        state: runtime.state,
        restarts: runtime.restarts,
    }
}

async fn read_persisted(path: &Path) -> anyhow::Result<BTreeMap<WorkloadName, ImageWorkload>> {
    match tokio::fs::read_to_string(path).await {
        Ok(text) => toml::from_str(&text).with_context(|| format!("parsing {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BTreeMap::new()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Replaces `path` with `data` atomically: a crash leaves either version, never a mix.
fn write_atomic(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;

    let tmp = path.with_extension("tmp");
    let mut file = std::fs::File::create(&tmp)?;
    file.write_all(data)?;
    file.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{MountSettings, RestartPolicy};

    fn parse<T: std::str::FromStr>(s: &str) -> T
    where
        T::Err: std::fmt::Debug,
    {
        s.parse().unwrap()
    }

    #[test]
    fn host_paths_are_absolute_and_normalized() {
        for valid in ["/", "/usr", "/run/dust-api/tls"] {
            assert_eq!(parse::<HostPath>(valid).as_str(), valid);
        }
        for invalid in ["", "usr", "/usr/", "//usr", "/run/../etc", "/./usr", "/a\0b"] {
            assert!(invalid.parse::<HostPath>().is_err(), "{invalid:?}");
        }
    }

    #[tokio::test]
    async fn persisted_workloads_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(PERSISTED);
        assert!(read_persisted(&path).await.unwrap().is_empty());

        let workload = ImageWorkload {
            image: parse("nginx:1.29"),
            command: vec!["nginx".into()],
            args: vec!["-g".into(), "daemon off;".into()],
            env: BTreeMap::from([(parse("A"), "1".to_owned())]),
            privileged: false,
            restart: RestartPolicy::OnFailure,
            mounts: vec![MountSettings {
                source: parse("/var/lib/web"),
                destination: parse("/data"),
                read_only: true,
            }],
            console: false,
        };
        let workloads = BTreeMap::from([(parse::<WorkloadName>("web"), workload)]);
        write_atomic(&path, toml::to_string_pretty(&workloads).unwrap().as_bytes()).unwrap();
        assert_eq!(read_persisted(&path).await.unwrap(), workloads);
        assert!(!path.with_extension("tmp").exists());

        std::fs::write(&path, "[web]\nimage = 1\n").unwrap();
        assert!(read_persisted(&path).await.is_err());
    }
}

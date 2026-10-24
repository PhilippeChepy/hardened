//! The supervision task of a workload: prepare, run, wait, clean up and restart.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::Instant;

use super::cri::{ContainerId, Cri, ImageId, Observed, SandboxId};
use super::events::{Exits, POLL_INTERVAL};
use super::logs::{self, ConsoleTail};
use super::pod::{self, HOST_FILES, Run};
use super::{BindMount, State};
use crate::settings::{ImageWorkload, RestartPolicy};
use crate::types::{ImageRef, WorkloadName};

/// Grace period when the manager goes away without asking for a stop.
const DEFAULT_GRACE: Duration = Duration::from_secs(10);
/// How long the runtime may take to kill a container after the grace period.
const KILL_TIMEOUT: Duration = Duration::from_secs(10);
/// How often the log of a `console` workload is copied to the console.
const CONSOLE_INTERVAL: Duration = Duration::from_millis(200);

const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_secs(60);
/// A workload running at least this long restarts after [`BACKOFF_MIN`] again.
const BACKOFF_RESET: Duration = Duration::from_secs(60);

/// The part of a workload's status its supervisor maintains.
#[derive(Debug, Clone)]
pub struct Runtime {
    pub state: State,
    pub restarts: u32,
}

pub type SharedRuntime = Arc<Mutex<Runtime>>;

/// What a supervisor needs.
pub struct Context {
    pub name: WorkloadName,
    pub definition: ImageWorkload,
    pub cri: Cri,
    pub exits: Exits,
    /// The workload's pod log directory.
    pub log_directory: PathBuf,
    pub runtime: SharedRuntime,
}

/// Owns a running supervision task.
pub struct Handle {
    stop: watch::Sender<Option<Duration>>,
    task: JoinHandle<()>,
}

impl Handle {
    pub fn spawn(context: Context) -> Self {
        let (stop, stop_rx) = watch::channel(None);
        let supervisor = Supervisor {
            // A new incarnation: its pods are told apart from those of earlier ones.
            uid: uuid::Uuid::new_v4().to_string(),
            attempt: 0,
            context,
            stop: stop_rx,
            sandbox: None,
            container: None,
            running_since: None,
        };
        Self {
            stop,
            task: tokio::spawn(supervisor.run()),
        }
    }

    /// Stops the workload (stop signal, then SIGKILL after `grace`) and waits for its cleanup.
    pub async fn stop(self, grace: Duration) {
        self.stop.send_replace(Some(grace));
        if let Err(e) = self.task.await {
            tracing::error!("workload supervisor failed: {e}");
        }
    }
}

enum Outcome {
    Exited { code: i32 },
    Stopped,
}

struct Supervisor {
    context: Context,
    uid: String,
    /// Runs started by this incarnation.
    attempt: u32,
    stop: watch::Receiver<Option<Duration>>,
    sandbox: Option<SandboxId>,
    container: Option<ContainerId>,
    running_since: Option<Instant>,
}

impl Supervisor {
    async fn run(mut self) {
        let name = self.context.name.clone();
        let mut backoff = Backoff::default();
        loop {
            self.running_since = None;
            let outcome = self.run_once().await;
            if let Err(e) = self.cleanup().await {
                tracing::warn!("workload {name}: cleaning up: {e:#}");
            }
            let restart = match outcome {
                Ok(Outcome::Stopped) => return,
                Ok(Outcome::Exited { code }) => self.restart_policy().restarts_after(code),
                Err(e) => {
                    // Failures before the workload ran (pull, sandbox, container creation) are
                    // retried whatever the policy: they are usually transient.
                    tracing::warn!("workload {name} failed: {e:#}");
                    self.set_state(State::Failed {
                        reason: format!("{e:#}"),
                    });
                    true
                }
            };
            if !restart {
                return;
            }

            let uptime = self.running_since.map(|t| t.elapsed()).unwrap_or_default();
            let delay = backoff.delay(uptime);
            tracing::info!("workload {name} restarting in {}s", delay.as_secs());
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                _ = stop_requested(&mut self.stop) => return,
            }
            self.update(|r| r.restarts += 1);
        }
    }

    async fn run_once(&mut self) -> anyhow::Result<Outcome> {
        let name = self.context.name.clone();
        let mut stop = self.stop.clone();
        self.set_state(State::Pending);

        // Until the container starts, a stop simply abandons the attempt: cleanup follows.
        let container = tokio::select! {
            container = self.create() => container?,
            _ = stop_requested(&mut stop) => return Ok(Outcome::Stopped),
        };
        let log_path = self.log_path();
        let mut console = match self.context.definition.console {
            true => Some(ConsoleTail::new(name.as_str(), &log_path).await),
            false => None,
        };
        // Subscribed before the start, so the exit cannot be missed.
        let mut exits = self.context.exits.subscribe();
        tokio::select! {
            started = self.context.cri.start_container(&container) => {
                started.context("starting the container")?;
            }
            _ = stop_requested(&mut stop) => return Ok(Outcome::Stopped),
        }
        self.running_since = Some(Instant::now());
        let pid = self.context.cri.container_pid(&container).await;
        self.set_state(State::Running { pid });
        tracing::info!("workload {name} started");

        let mut poll = tokio::time::interval(POLL_INTERVAL);
        let mut checked: Instant;
        let mut tick = tokio::time::interval(CONSOLE_INTERVAL);
        let mut stopping = false;
        let code = 'wait: loop {
            let state = self
                .context
                .cri
                .container_state(&container)
                .await
                .context("reading the container's status")?;
            checked = Instant::now();
            if let Observed::Exited { code } = state {
                break 'wait code;
            }
            loop {
                tokio::select! {
                    () = exits.changed(&container) => break,
                    _ = poll.tick() => if checked.elapsed() >= exits.poll_interval() { break },
                    grace = stop_requested(&mut stop), if !stopping => {
                        stopping = true;
                        tracing::info!("workload {name} stopping");
                        let stopped = self.context.cri.stop_container(&container, grace);
                        match tokio::time::timeout(grace + KILL_TIMEOUT, stopped).await {
                            Ok(result) => result.context("stopping the container")?,
                            Err(_) => anyhow::bail!("still running {KILL_TIMEOUT:?} after its grace period"),
                        }
                        break;
                    }
                    _ = tick.tick(), if console.is_some() => {
                        if let Some(console) = &mut console {
                            console.poll().await;
                        }
                    }
                }
            }
        };

        if let Some(console) = console {
            // The runtime may still be writing the last output it read from the container.
            tokio::time::sleep(CONSOLE_INTERVAL).await;
            console.finish().await;
        }
        tracing::info!("workload {name} exited with code {code}");
        self.set_state(State::Exited { code });
        Ok(if stopping {
            Outcome::Stopped
        } else {
            Outcome::Exited { code }
        })
    }

    /// Runs the sandbox and creates the container, after removing the leftovers of earlier runs.
    async fn create(&mut self) -> anyhow::Result<ContainerId> {
        let cri = self.context.cri.clone();
        let name = self.context.name.clone();
        self.remove_leftovers().await.context("removing leftovers")?;
        let image = self.ensure_image().await?;

        let host_files = host_files().await;
        tokio::fs::create_dir_all(&self.context.log_directory)
            .await
            .with_context(|| format!("creating {}", self.context.log_directory.display()))?;
        logs::rotate(&self.log_path()).await;

        let run = Run {
            name: &name,
            uid: &self.uid,
            attempt: self.attempt,
            log_directory: &self.context.log_directory,
        };
        self.attempt += 1;
        let sandbox_config = pod::sandbox_config(&run, &self.context.definition);
        let container_config = pod::image_container(&run, &self.context.definition, &image, &host_files);

        let sandbox = cri
            .run_sandbox(sandbox_config.clone())
            .await
            .context("running the pod sandbox")?;
        self.sandbox = Some(sandbox.clone());
        let container = cri
            .create_container(&sandbox, container_config, sandbox_config)
            .await
            .context("creating the container")?;
        self.container = Some(container.clone());
        Ok(container)
    }

    /// The runtime's ID of the workload's image, pulling it if needed.
    async fn ensure_image(&self) -> anyhow::Result<ImageId> {
        let reference = &self.context.definition.image;
        let present = self
            .context
            .cri
            .image_id(reference)
            .await
            .with_context(|| format!("looking up {reference}"))?;
        match present {
            Some(id) => Ok(id),
            None => self.pull(reference).await,
        }
    }

    async fn pull(&self, reference: &ImageRef) -> anyhow::Result<ImageId> {
        let name = &self.context.name;
        self.set_state(State::Pulling);
        tracing::info!("workload {name}: pulling {reference}");
        let id = self
            .context
            .cri
            .pull(reference)
            .await
            .with_context(|| format!("pulling {reference}"))?;
        tracing::info!("workload {name}: pulled {reference}");
        Ok(id)
    }

    /// Removes the pods of this workload left by an earlier run or incarnation.
    async fn remove_leftovers(&self) -> anyhow::Result<()> {
        let cri = &self.context.cri;
        for (sandbox, _) in cri.sandboxes(pod::workload_selector(&self.context.name)).await? {
            tracing::debug!("workload {}: removing pod sandbox {sandbox}", self.context.name);
            cri.remove_sandbox(&sandbox).await?;
        }
        Ok(())
    }

    /// Removes the container and sandbox of the last run, if they exist.
    async fn cleanup(&mut self) -> anyhow::Result<()> {
        let cri = &self.context.cri;
        if let Some(container) = &self.container {
            cri.remove_container(container)
                .await
                .context("removing the container")?;
            self.container = None;
        }
        if let Some(sandbox) = &self.sandbox {
            cri.stop_sandbox(sandbox).await.context("stopping the pod sandbox")?;
            cri.remove_sandbox(sandbox).await.context("removing the pod sandbox")?;
            self.sandbox = None;
        }
        Ok(())
    }

    fn log_path(&self) -> PathBuf {
        self.context.log_directory.join(pod::log_file(&self.context.name))
    }

    fn restart_policy(&self) -> RestartPolicy {
        self.context.definition.restart
    }

    fn set_state(&self, state: State) {
        self.update(|r| r.state = state);
    }

    fn update(&self, f: impl FnOnce(&mut Runtime)) {
        f(&mut self.context.runtime.lock().unwrap_or_else(|e| e.into_inner()));
    }
}

/// The present [`HOST_FILES`].
async fn host_files() -> Vec<BindMount> {
    let mut mounts = Vec::new();
    for (source, destination) in HOST_FILES {
        if !tokio::fs::try_exists(source).await.unwrap_or(false) {
            continue;
        }
        // Valid paths, as tested.
        let (Ok(source), Ok(destination)) = (source.parse(), destination.parse()) else {
            continue;
        };
        mounts.push(BindMount {
            source,
            destination,
            read_only: true,
        });
    }
    mounts
}

/// Resolves once a stop is requested, with its grace period.
async fn stop_requested(stop: &mut watch::Receiver<Option<Duration>>) -> Duration {
    match stop.wait_for(Option::is_some).await {
        Ok(grace) => grace.unwrap_or(DEFAULT_GRACE),
        // The manager is gone.
        Err(_) => DEFAULT_GRACE,
    }
}

/// Exponential restart delay, reset once a workload ran for [`BACKOFF_RESET`].
#[derive(Debug)]
struct Backoff {
    next: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self { next: BACKOFF_MIN }
    }
}

impl Backoff {
    fn delay(&mut self, uptime: Duration) -> Duration {
        if uptime >= BACKOFF_RESET {
            self.next = BACKOFF_MIN;
        }
        let delay = self.next;
        self.next = (self.next * 2).min(BACKOFF_MAX);
        delay
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_doubles_up_to_a_minute_and_resets() {
        let mut backoff = Backoff::default();
        let delays: Vec<u64> = (0..8).map(|_| backoff.delay(Duration::ZERO).as_secs()).collect();
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(backoff.delay(Duration::from_secs(59)).as_secs(), 60);
        assert_eq!(backoff.delay(Duration::from_secs(60)).as_secs(), 1);
        assert_eq!(backoff.delay(Duration::ZERO).as_secs(), 2);
    }

    #[test]
    fn host_files_are_valid_paths() {
        for (source, destination) in HOST_FILES {
            assert!(source.parse::<super::super::HostPath>().is_ok());
            assert!(destination.parse::<crate::types::ContainerPath>().is_ok());
        }
    }
}

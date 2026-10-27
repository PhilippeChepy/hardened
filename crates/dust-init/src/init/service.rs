//! Host daemons of the image run by dust-init (containerd, kubelet), unconfined: restarted with
//! backoff whenever they exit. Their output goes to a log file on `/var` (copied and truncated
//! when it grows too large); the end of a crashed run is copied to dust-init's log, and so to the
//! console.

use std::fs::OpenOptions;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::process::Signal;
use tokio::sync::{Mutex, watch};
use tracing::{info, warn};

use crate::process::{Child, Reaper};

/// Lines of a crashed run's output copied to dust-init's log, and how many crashes in a row get
/// that before a crash loop is left to the log file alone.
const CRASH_LINES: usize = 20;
const CRASHES_SHOWN: u32 = 3;
/// A run this long counts as healthy: the backoff and the crash count start over.
const HEALTHY_RUN: Duration = Duration::from_secs(60);
const MAX_BACKOFF: Duration = Duration::from_secs(30);
/// Past this size, a log is copied to `<log>.1` and truncated (the daemon keeps appending to it).
const MAX_LOG_SIZE: u64 = 64 << 20;
const LOG_CHECK_INTERVAL: Duration = Duration::from_secs(60);

/// What to run.
pub struct Spec {
    /// Names it in dust-init's log.
    pub name: &'static str,
    pub program: &'static str,
    pub args: Vec<String>,
    pub log: &'static str,
}

/// A supervised daemon.
pub struct Service {
    name: &'static str,
    stop: watch::Sender<bool>,
    child: Arc<Mutex<Option<u32>>>,
    supervisor: tokio::task::JoinHandle<()>,
}

impl Service {
    pub fn start(reaper: Reaper, spec: Spec) -> Self {
        let (stop, stopped) = watch::channel(false);
        let child = Arc::new(Mutex::new(None));
        let name = spec.name;
        let supervisor = tokio::spawn(supervise(reaper, spec, child.clone(), stopped));
        Self {
            name,
            stop,
            child,
            supervisor,
        }
    }

    /// SIGTERM, then SIGKILL after `grace`.
    pub async fn stop(self, grace: Duration) {
        let _ = self.stop.send(true);
        if let Some(pid) = *self.child.lock().await {
            signal(pid, Signal::TERM);
        }
        let supervisor = self.supervisor;
        tokio::pin!(supervisor);
        if tokio::time::timeout(grace, &mut supervisor).await.is_err() {
            if let Some(pid) = *self.child.lock().await {
                warn!("{} did not stop in {grace:?}, killing it", self.name);
                signal(pid, Signal::KILL);
            }
            let _ = supervisor.await;
        }
    }
}

async fn supervise(reaper: Reaper, spec: Spec, pid: Arc<Mutex<Option<u32>>>, mut stopped: watch::Receiver<bool>) {
    let name = spec.name;
    let mut backoff = Duration::from_secs(1);
    let mut crashes = 0;
    loop {
        let started = Instant::now();
        // Where this run's output starts in the log.
        let offset = std::fs::metadata(spec.log).map_or(0, |m| m.len());
        let process = match spawn(&reaper, &spec) {
            Ok(process) => process,
            Err(e) => {
                warn!("cannot start {name}: {e}");
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stopped.changed() => return,
                }
                backoff = (backoff * 2).min(MAX_BACKOFF);
                continue;
            }
        };
        info!(pid = process.pid, "{name} started");
        *pid.lock().await = Some(process.pid);
        let exit = {
            let wait = process.wait();
            tokio::pin!(wait);
            let mut check = tokio::time::interval(LOG_CHECK_INTERVAL);
            loop {
                tokio::select! {
                    exit = &mut wait => break exit,
                    _ = check.tick() => rotate(Path::new(spec.log), MAX_LOG_SIZE).await,
                }
            }
        };
        *pid.lock().await = None;
        if *stopped.borrow_and_update() {
            info!(%exit, "{name} stopped");
            return;
        }
        warn!(%exit, "{name} exited, restarting in {backoff:?}");
        if started.elapsed() > HEALTHY_RUN {
            backoff = Duration::from_secs(1);
            crashes = 0;
        }
        crashes += 1;
        if crashes <= CRASHES_SHOWN {
            copy_output(name, spec.log, offset, CRASH_LINES);
        } else if crashes == CRASHES_SHOWN + 1 {
            warn!("{name} keeps crashing; its output stays in {}", spec.log);
        }
        tokio::select! {
            _ = tokio::time::sleep(backoff) => {}
            _ = stopped.changed() => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

fn spawn(reaper: &Reaper, spec: &Spec) -> std::io::Result<Child> {
    let log = OpenOptions::new().create(true).append(true).open(spec.log)?;
    let mut command = Command::new(spec.program);
    command
        .args(&spec.args)
        .env_clear()
        // Where CNI plugins (which inherit containerd's environment) find iptables and nft.
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    reaper.spawn(&mut command)
}

/// Copies a log grown past `max_size` to `<log>.1`, then truncates it: the daemon holds it open
/// in append mode, so renaming it would not make it start a new one.
async fn rotate(log: &Path, max_size: u64) {
    let Ok(metadata) = tokio::fs::metadata(log).await else {
        return;
    };
    if metadata.len() <= max_size {
        return;
    }
    let rotated = log.with_extension("log.1");
    let result = async {
        tokio::fs::copy(log, &rotated).await?;
        tokio::fs::OpenOptions::new()
            .write(true)
            .open(log)
            .await?
            .set_len(0)
            .await
    };
    if let Err(e) = result.await {
        warn!("rotating {}: {e}", log.display());
    }
}

fn signal(pid: u32, signal: Signal) {
    if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
        let _ = rustix::process::kill_process(pid, signal);
    }
}

/// Copies the last `lines` lines of `log` to dust-init's log (and so the console).
pub fn log_tail(name: &str, log: &str, lines: usize) {
    copy_output(name, log, 0, lines);
}

/// Copies the last `lines` lines written to `log` from `offset` on.
fn copy_output(name: &str, log: &str, offset: u64, lines: usize) {
    let text = match std::fs::read(log) {
        Ok(text) => text,
        Err(e) => return warn!("cannot read {log}: {e}"),
    };
    let output = text
        .get(usize::try_from(offset).unwrap_or(usize::MAX)..)
        .unwrap_or_default();
    for line in last_lines(&String::from_utf8_lossy(output), lines) {
        warn!("{name}: {line}");
    }
}

fn last_lines(text: &str, count: usize) -> impl Iterator<Item = &str> {
    let all: Vec<&str> = text.lines().collect();
    let skip = all.len().saturating_sub(count);
    all.into_iter().skip(skip)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_the_last_lines() {
        assert_eq!(last_lines("a\nb\nc\n", 2).collect::<Vec<_>>(), ["b", "c"]);
        assert_eq!(last_lines("a", 5).collect::<Vec<_>>(), ["a"]);
        assert_eq!(last_lines("", 5).count(), 0);
    }

    #[tokio::test]
    async fn rotates_large_logs() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("daemon.log");
        std::fs::write(&log, "small").unwrap();
        rotate(&log, 5).await;
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "small");
        assert!(!dir.path().join("daemon.log.1").exists());

        std::fs::write(&log, "larger").unwrap();
        rotate(&log, 5).await;
        assert_eq!(std::fs::read_to_string(&log).unwrap(), "");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("daemon.log.1")).unwrap(),
            "larger"
        );
    }
}

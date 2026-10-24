//! The containerd daemon, supervised by dust-init: restarted with backoff whenever it exits.

use std::fs::OpenOptions;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustix::process::Signal;
use tokio::sync::{Mutex, watch};
use tracing::{info, warn};

use crate::process::{Child, Reaper};

pub const SOCKET: &str = "/run/containerd/containerd.sock";
const CONFIG: &str = "/usr/share/hardened/containerd/config.toml";
const LOG: &str = "/var/log/containerd.log";
/// Lines of a crashed run's output copied to dust-init's log, and how many crashes in a row get
/// that before a crash loop is left to the log file alone.
const CRASH_LINES: usize = 20;
const CRASHES_SHOWN: u32 = 3;
/// A run this long counts as healthy: the backoff and the crash count start over.
const HEALTHY_RUN: Duration = Duration::from_secs(60);

pub struct Containerd {
    stop: watch::Sender<bool>,
    child: Arc<Mutex<Option<u32>>>,
    supervisor: tokio::task::JoinHandle<()>,
}

impl Containerd {
    pub fn start(reaper: Reaper) -> Self {
        let (stop, mut stopped) = watch::channel(false);
        let child = Arc::new(Mutex::new(None));
        let pid = child.clone();
        let supervisor = tokio::spawn(async move {
            let mut backoff = Duration::from_secs(1);
            let mut crashes = 0;
            loop {
                let started = Instant::now();
                // Where this run's output starts in the log.
                let offset = std::fs::metadata(LOG).map_or(0, |m| m.len());
                let process = match spawn(&reaper) {
                    Ok(process) => process,
                    Err(e) => {
                        warn!("cannot start containerd: {e}");
                        tokio::time::sleep(backoff).await;
                        continue;
                    }
                };
                info!(pid = process.pid, "containerd started");
                *pid.lock().await = Some(process.pid);
                let exit = process.wait().await;
                *pid.lock().await = None;
                if *stopped.borrow_and_update() {
                    info!(%exit, "containerd stopped");
                    return;
                }
                warn!(%exit, "containerd exited, restarting in {backoff:?}");
                if started.elapsed() > HEALTHY_RUN {
                    backoff = Duration::from_secs(1);
                    crashes = 0;
                }
                crashes += 1;
                if crashes <= CRASHES_SHOWN {
                    copy_output(offset, CRASH_LINES);
                } else if crashes == CRASHES_SHOWN + 1 {
                    warn!("containerd keeps crashing; its output stays in {LOG}");
                }
                tokio::select! {
                    _ = tokio::time::sleep(backoff) => {}
                    _ = stopped.changed() => return,
                }
                backoff = (backoff * 2).min(Duration::from_secs(30));
            }
        });
        Self {
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
                warn!("containerd did not stop in {grace:?}, killing it");
                signal(pid, Signal::KILL);
            }
            let _ = supervisor.await;
        }
    }
}

fn spawn(reaper: &Reaper) -> std::io::Result<Child> {
    let log = OpenOptions::new().create(true).append(true).open(LOG)?;
    let mut command = Command::new("/usr/bin/containerd");
    command
        .args(["--config", CONFIG])
        .env_clear()
        .env("PATH", "/usr/bin")
        .stdin(Stdio::null())
        .stdout(log.try_clone()?)
        .stderr(log);
    reaper.spawn(&mut command)
}

fn signal(pid: u32, signal: Signal) {
    if let Some(pid) = rustix::process::Pid::from_raw(pid as i32) {
        let _ = rustix::process::kill_process(pid, signal);
    }
}

/// Copies the last `lines` lines of containerd's log to dust-init's log (and so the console).
pub fn log_tail(lines: usize) {
    copy_output(0, lines);
}

/// Copies the last `lines` lines written to containerd's log from `offset` on.
fn copy_output(offset: u64, lines: usize) {
    let log = match std::fs::read(LOG) {
        Ok(log) => log,
        Err(e) => return warn!("cannot read {LOG}: {e}"),
    };
    let output = log
        .get(usize::try_from(offset).unwrap_or(usize::MAX)..)
        .unwrap_or_default();
    for line in last_lines(&String::from_utf8_lossy(output), lines) {
        warn!("containerd: {line}");
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
}

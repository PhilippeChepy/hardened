//! Child processes of PID 1.
//!
//! As init, dust-init inherits every orphaned process (containerd shims double-fork) and must reap
//! them, so it calls `waitpid(-1)` on each SIGCHLD. That would steal the exit status of children
//! spawned with `std::process`/`tokio::process`, which wait on their own pid. Every child of dust-init
//! is therefore spawned through [`Reaper::spawn`]: it records the pid under the same lock the
//! reaper holds while waiting, so a child exiting immediately cannot be missed.

use std::collections::HashMap;
use std::process::Command;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use rustix::process::{WaitOptions, WaitStatus};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::oneshot;

/// How a child process ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

impl Exit {
    fn from_status(status: WaitStatus) -> Self {
        match (status.exit_status(), status.terminating_signal()) {
            (Some(code), _) => Self::Code(code),
            (None, Some(signal)) => Self::Signal(signal),
            (None, None) => Self::Code(-1),
        }
    }
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code(code) => write!(f, "exit code {code}"),
            Self::Signal(signal) => write!(f, "signal {signal}"),
        }
    }
}

/// A running child.
pub struct Child {
    pub pid: u32,
    exit: oneshot::Receiver<Exit>,
}

impl Child {
    pub async fn wait(self) -> Exit {
        // The sender is only dropped by the reaper after sending.
        self.exit.await.unwrap_or(Exit::Code(-1))
    }
}

#[derive(Clone)]
pub struct Reaper {
    waiters: Arc<Mutex<HashMap<u32, oneshot::Sender<Exit>>>>,
}

impl Reaper {
    /// Starts reaping. Must be called before any child is spawned.
    pub fn start() -> anyhow::Result<Self> {
        let reaper = Self {
            waiters: Arc::default(),
        };
        let mut sigchld = signal(SignalKind::child()).context("installing the SIGCHLD handler")?;
        let task = reaper.clone();
        tokio::spawn(async move {
            loop {
                task.reap();
                sigchld.recv().await;
            }
        });
        Ok(reaper)
    }

    /// Collects every exited child, notifying the ones spawned through [`Reaper::spawn`].
    fn reap(&self) {
        let mut waiters = self.waiters.lock().unwrap_or_else(|e| e.into_inner());
        while let Ok(Some((pid, status))) = rustix::process::wait(WaitOptions::NOHANG) {
            let pid = pid.as_raw_nonzero().get() as u32;
            match waiters.remove(&pid) {
                Some(waiter) => {
                    let _ = waiter.send(Exit::from_status(status));
                }
                None => tracing::debug!(pid, "reaped orphan"),
            }
        }
    }

    /// Spawns `command`. Its standard streams default to dust-init's (the console).
    pub fn spawn(&self, command: &mut Command) -> std::io::Result<Child> {
        let mut waiters = self.waiters.lock().unwrap_or_else(|e| e.into_inner());
        let child = command.spawn()?;
        let pid = child.id();
        let (tx, rx) = oneshot::channel();
        waiters.insert(pid, tx);
        // `std::process::Child` never waits unless asked to; dropping it is fine.
        drop(child);
        Ok(Child { pid, exit: rx })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waits_for_children() {
        let reaper = Reaper::start().unwrap();
        let child = reaper.spawn(Command::new("sh").args(["-c", "exit 3"])).unwrap();
        assert_eq!(child.wait().await, Exit::Code(3));

        let child = reaper.spawn(&mut Command::new("true")).unwrap();
        assert_eq!(child.wait().await, Exit::Code(0));
    }
}

//! Child processes of PID 1.
//!
//! As init, serviced inherits every orphaned process (containerd shims double-fork) and must reap
//! them, so it calls `waitpid(-1)` on each SIGCHLD. That would steal the exit status of children
//! spawned with `std::process`/`tokio::process`, which wait on their own pid. Every child of
//! serviced is therefore spawned through [`Reaper::spawn`]: it records the pid under the same lock
//! the reaper holds while waiting, so a child exiting immediately cannot be missed (and std's own
//! `waitpid` after a failed `exec` cannot race with the reaper).

use std::collections::HashMap;
use std::io;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use rustix::io::Errno;
use rustix::process::{Pid, Signal, WaitId, WaitIdOptions, WaitOptions, WaitStatus};
use tokio::signal::unix::{self, SignalKind};
use tokio::sync::{Mutex, oneshot, watch};

use crate::exit::Exit;

/// The exit of a child, as `waitpid` reported it.
#[must_use]
fn exit_of(status: WaitStatus) -> Exit {
    match (status.exit_status(), status.terminating_signal()) {
        (Some(code), _) => Exit::Code(code),
        (None, Some(signal)) => Exit::Signal(signal),
        (None, None) => Exit::Code(-1),
    }
}

/// A running child.
pub struct Child {
    /// Its process ID.
    pub pid: u32,
    exit: oneshot::Receiver<Exit>,
}

impl Child {
    /// Waits for the child to exit, once the reaper collected it.
    pub async fn wait(self) -> Exit {
        // The sender is only dropped by the reaper after sending.
        self.exit.await.unwrap_or(Exit::Code(-1))
    }
}

/// Collects every exited process, and reports the exit of the children spawned through it.
#[derive(Clone)]
pub struct Reaper {
    waiters: Arc<Mutex<HashMap<u32, oneshot::Sender<Exit>>>>,
    /// Changed after each pass.
    reaped: Arc<watch::Sender<()>>,
}

impl Reaper {
    /// Starts reaping. Must be called before any child is spawned.
    pub fn start() -> anyhow::Result<Self> {
        use anyhow::Context as _;

        let reaper = Self {
            waiters: Arc::default(),
            reaped: Arc::new(watch::Sender::new(())),
        };
        let mut sigchld =
            unix::signal(SignalKind::child()).context("installing the SIGCHLD handler")?;
        let task = reaper.clone();
        tokio::spawn(async move {
            loop {
                task.reap().await;
                sigchld.recv().await;
            }
        });
        Ok(reaper)
    }

    /// Collects every exited child, notifying the ones spawned through [`Reaper::spawn`].
    async fn reap(&self) {
        let mut waiters = self.waiters.lock().await;
        while let Ok(Some((pid, status))) = rustix::process::wait(WaitOptions::NOHANG) {
            let pid = pid.as_raw_nonzero().get() as u32;
            match waiters.remove(&pid) {
                Some(waiter) => {
                    let _ = waiter.send(exit_of(status));
                }
                None => tracing::debug!(pid, "reaped orphan"),
            }
        }
        self.reaped.send_replace(());
    }

    /// Waits up to `timeout` for every child to be reaped; returns whether none is left.
    #[must_use]
    pub async fn wait_for_no_children(&self, timeout: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + timeout;
        // Before checking: a pass after the check is seen.
        let mut reaped = self.reaped.subscribe();
        loop {
            if no_children() {
                return true;
            }
            if tokio::time::timeout_at(deadline, reaped.changed())
                .await
                .is_err()
            {
                return no_children();
            }
        }
    }

    /// Spawns `command`, registering it before the reaper can collect it.
    pub async fn spawn(&self, command: &mut Command) -> io::Result<Child> {
        let mut waiters = self.waiters.lock().await;
        // `std::process::Child` never waits unless asked to; dropping it is fine.
        let pid = command.spawn()?.id();
        let (tx, rx) = oneshot::channel();
        waiters.insert(pid, tx);
        Ok(Child { pid, exit: rx })
    }
}

/// Whether PID 1 has no child left (exited ones not reaped yet count): every user process
/// descends from it.
#[must_use]
pub fn no_children() -> bool {
    let options = WaitIdOptions::EXITED | WaitIdOptions::NOHANG | WaitIdOptions::NOWAIT;
    matches!(
        rustix::process::waitid(WaitId::All, options),
        Err(Errno::CHILD)
    )
}

/// Sends `signal` to `pid`, if it still exists.
pub fn signal_process(pid: u32, signal: i32) {
    let (Some(pid), Some(signal)) = (Pid::from_raw(pid as i32), Signal::from_named_raw(signal))
    else {
        return;
    };
    let _ = rustix::process::kill_process(pid, signal);
}

/// The reaper of the tests, on a runtime of its own: two reapers in one process would collect
/// each other's children.
#[cfg(test)]
pub fn test_reaper() -> Reaper {
    use std::sync::OnceLock;

    static REAPER: OnceLock<Reaper> = OnceLock::new();
    let reaper = REAPER.get_or_init(|| {
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                tx.send(Reaper::start().unwrap()).unwrap();
                std::future::pending::<()>().await;
            });
        });
        rx.recv().unwrap()
    });
    reaper.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waits_for_children() {
        let reaper = test_reaper();
        let child = reaper
            .spawn(Command::new("sh").args(["-c", "exit 3"]))
            .await
            .unwrap();
        assert_eq!(child.wait().await, Exit::Code(3));

        let child = reaper.spawn(&mut Command::new("true")).await.unwrap();
        assert_eq!(child.wait().await, Exit::Code(0));

        let child = reaper.spawn(Command::new("sleep").arg("10")).await.unwrap();
        signal_process(child.pid, libc::SIGTERM);
        assert_eq!(child.wait().await, Exit::Signal(libc::SIGTERM));

        assert!(
            reaper
                .spawn(&mut Command::new("/nonexistent"))
                .await
                .is_err()
        );
    }
}

//! Child processes of PID 1.
//!
//! As init, dust-init inherits every orphaned process (containerd shims double-fork) and must reap
//! them, so it calls `waitpid(-1)` on each SIGCHLD. That would steal the exit status of children
//! spawned with `std::process`/`tokio::process`, which wait on their own pid. Every child of dust-init
//! is therefore spawned through [`Reaper::spawn`]: it records the pid under the same lock the
//! reaper holds while waiting, so a child exiting immediately cannot be missed.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::process::{Command, Stdio};
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
        // `std::process::Child` never waits unless asked to; dropping it is fine.
        self.spawn_std(command).map(|(child, _)| child)
    }

    /// Runs `command` to completion, `input` on its standard input, and collects its output.
    /// `input` must fit in a pipe (64 KiB): it is written before the output is read.
    pub async fn output(&self, command: &mut Command, input: &[u8]) -> std::io::Result<Output> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let (child, mut std_child) = self.spawn_std(command)?;
        let (Some(mut stdin), Some(mut stdout), Some(mut stderr)) =
            (std_child.stdin.take(), std_child.stdout.take(), std_child.stderr.take())
        else {
            unreachable!("every stream is piped");
        };
        // A copy the blocking task owns; it may be a key, so it is wiped once written.
        let input = zeroize::Zeroizing::new(input.to_vec());
        let io = tokio::task::spawn_blocking(move || {
            // A program exiting without reading its input is judged by its exit status.
            match stdin.write_all(&input) {
                Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => return Err(e),
                _ => drop(stdin),
            }
            let errors = std::thread::spawn(move || {
                let mut buffer = Vec::new();
                stderr.read_to_end(&mut buffer).map(|_| buffer)
            });
            let mut out = Vec::new();
            stdout.read_to_end(&mut out)?;
            let err = errors
                .join()
                .map_err(|_| std::io::Error::other("stderr reader panicked"))??;
            Ok((out, err))
        });
        let exit = child.wait().await;
        let (stdout, stderr) = io.await.map_err(std::io::Error::other)??;
        Ok(Output { exit, stdout, stderr })
    }

    /// Spawns `command`, registering it before the reaper can collect it.
    fn spawn_std(&self, command: &mut Command) -> std::io::Result<(Child, std::process::Child)> {
        let mut waiters = self.waiters.lock().unwrap_or_else(|e| e.into_inner());
        let child = command.spawn()?;
        let pid = child.id();
        let (tx, rx) = oneshot::channel();
        waiters.insert(pid, tx);
        Ok((Child { pid, exit: rx }, child))
    }
}

/// What [`Reaper::output`] collected.
#[derive(Debug)]
pub struct Output {
    pub exit: Exit,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn waits_for_children_and_collects_output() {
        let reaper = Reaper::start().unwrap();
        let child = reaper.spawn(Command::new("sh").args(["-c", "exit 3"])).unwrap();
        assert_eq!(child.wait().await, Exit::Code(3));

        let child = reaper.spawn(&mut Command::new("true")).unwrap();
        assert_eq!(child.wait().await, Exit::Code(0));

        // In the same test: two reapers in one process would collect each other's children.
        let script = "read line; echo \"got $line\"; echo oops >&2; exit 2";
        let output = reaper
            .output(Command::new("sh").args(["-c", script]), b"key\n")
            .await
            .unwrap();
        assert_eq!(output.exit, Exit::Code(2));
        assert_eq!(output.stdout, b"got key\n");
        assert_eq!(output.stderr, b"oops\n");

        let output = reaper.output(&mut Command::new("true"), &[0; 4096]).await.unwrap();
        assert_eq!(output.exit, Exit::Code(0));
    }
}

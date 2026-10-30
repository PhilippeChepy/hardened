//! What serviced tells of a service: where it is in its life, and how its runs went.

use std::time::SystemTime;

use crate::exit::Exit;

/// Where a service is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Disabled, or its condition is false.
    Inactive,
    /// For the services it requires.
    Waiting,
    /// Running `exec-pre`.
    Starting,
    /// `exec` runs; not ready yet (a `notify` service that has not sent `READY=1`).
    Running,
    /// `exec` runs and is ready.
    Ready,
    /// `exec` exited and is not restarted (`restart = "never"`, or `on-failure` after a success).
    Exited,
    /// It could not start, or it exited and is not restarted; or a service it requires failed.
    Failed,
    /// Waiting to start `exec` again.
    Backoff,
    /// Being stopped: its process was signalled, or its `exec-post` or `exec-stop` commands run.
    Stopping,
    /// Stopped on request or at shutdown.
    Stopped,
}

/// A service's state and the history of its runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub state: State,
    /// When it entered `state`.
    pub since: SystemTime,
    /// The main process, while it runs.
    pub pid: Option<u32>,
    /// How many times `exec` was started again after exiting, by the restart policy.
    pub restarts: u32,
    /// How `exec` last ended, if it did.
    pub last_exit: Option<Exit>,
    /// Why it is waiting, inactive or failed.
    pub reason: Option<String>,
    /// The last `STATUS=` of this run, from its notify socket.
    pub status_text: String,
}

impl ServiceStatus {
    /// A service just entered `state`, without a process nor history.
    #[must_use]
    pub fn new(state: State) -> Self {
        Self {
            state,
            since: SystemTime::now(),
            pid: None,
            restarts: 0,
            last_exit: None,
            reason: None,
            status_text: String::new(),
        }
    }
}

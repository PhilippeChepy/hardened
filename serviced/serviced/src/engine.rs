//! The services' life cycle, as a state machine: serviced feeds it the service files, what
//! becomes of their processes and what is asked through its API; it answers with [`Action`]s
//! (start, stop, schedule a restart) and keeps each service's [`ServiceStatus`]. It runs no
//! process and reads no file but through the `exists` probe of conditions, and it is given the
//! time, so it is tested without being PID 1.
//!
//! A service is started once it is enabled, the services it `requires` are ready, and its
//! condition holds. Requirements are checked at
//! every start, restarts included: a service whose requirement failed, is inactive or missing
//! does not start (it is failed or inactive, and is checked again whenever something changes);
//! one already running is left alone when a requirement goes away. A service stopped on request
//! stays stopped until started or restarted.
//!
//! A socket-activated service (with an `activate` socket) is inactive until activated: by a
//! connection to one of those sockets ([`Event::Activated`]), by a request to start it, or by a
//! service requiring it that could otherwise start. Once its run is over and not restarted by its
//! policy, it waits for the next connection ([`Engine::awaiting_connection`]).
//!
//! Stopping a service (on request, when disabled or removed) runs its `exec-stop` once its
//! process is gone. At shutdown, the running services stop first, dependents first
//! ([`Engine::shutdown`]), their `exec-stop` left for later; once every other process is gone, the
//! `exec-stop` of every service that ran runs, one at a time, in reverse start order
//! ([`Engine::run_exec_stops`], [`Action::ExecStop`]), so that what they undo (`/var`) is no
//! longer in use.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};

use libserviced::definition::{Restart, Service, ServiceName, SocketName};
use toml::Table;
use tracing::{debug, info, warn};

use crate::exit::Exit;
use crate::notification::Notification;
use crate::service_status::{ServiceStatus, State};

/// The delay before the first restart; it doubles at each failure in a row, up to
/// [`MAX_BACKOFF`].
const FIRST_BACKOFF: Duration = Duration::from_secs(1);
const MAX_BACKOFF: Duration = Duration::from_secs(60);
/// A run this long counts as healthy: the backoff and the crash count start over.
const HEALTHY_RUN: Duration = Duration::from_secs(60);
/// Failures in a row whose output tail is copied to serviced's log.
const CRASHES_SHOWN: u32 = 3;

/// One run of a service: its `exec-pre`, `exec` and `exec-post`. Events of older runs are ignored.
pub type RunId = u64;

/// What happened to a service's run.
#[derive(Debug)]
pub enum Event {
    /// `exec` started.
    Started {
        service: ServiceName,
        run: RunId,
        pid: u32,
    },
    /// A process of the service sent `notification` on its notify socket.
    Notified {
        service: ServiceName,
        pid: u32,
        notification: Notification,
    },
    /// `exec` exited; `exec-post` runs next.
    Exited {
        service: ServiceName,
        run: RunId,
        exit: Exit,
    },
    /// The run is over, `exec-post` included.
    Finished {
        service: ServiceName,
        run: RunId,
        outcome: Outcome,
    },
    /// The delay before a restart is over.
    BackoffElapsed { service: ServiceName, token: u64 },
    /// A connection waits on `socket`, of socket-activated `service`.
    Activated {
        service: ServiceName,
        socket: SocketName,
    },
}

/// How a run ended.
#[derive(Debug, PartialEq)]
pub enum Outcome {
    /// `exec` did not run: why (an `exec-pre` failed, the program could not be started, the
    /// run was stopped first), and the last lines of output.
    NotStarted { reason: String, tail: Vec<String> },
    /// `exec` ran and exited, and the last lines of output.
    Exited { exit: Exit, tail: Vec<String> },
}

/// What serviced must do.
#[derive(Debug)]
pub enum Action {
    /// Run the service (as defined here, whatever its file becomes meanwhile).
    Start {
        service: ServiceName,
        run: RunId,
        definition: Arc<Service>,
    },
    /// Stop the run: SIGTERM, SIGKILL after the stop timeout, then `exec-post`, and `exec-stop`
    /// unless it is left for later (at shutdown).
    Stop {
        service: ServiceName,
        run: RunId,
        exec_stop: bool,
    },
    /// Run the `exec-stop` left for later at shutdown (as defined here), as run `run`.
    ExecStop {
        service: ServiceName,
        run: RunId,
        definition: Arc<Service>,
    },
    /// Send [`Event::BackoffElapsed`] after `delay`.
    Schedule {
        service: ServiceName,
        token: u64,
        delay: Duration,
    },
    /// Copy the end of a failed run's output to serviced's log.
    ShowCrash {
        service: ServiceName,
        lines: Vec<String>,
    },
}

/// Why a request about a service is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    #[error("no such service")]
    Unknown,
    #[error("the machine is shutting down")]
    ShuttingDown,
}

/// The services and their life cycles.
pub struct Engine {
    entries: BTreeMap<ServiceName, Entry>,
    /// Whether a path exists, for conditions.
    exists: Box<dyn Fn(&Path) -> bool + Send + Sync>,
    /// Services on a cycle of `requires`: they would wait forever.
    cyclic: BTreeSet<ServiceName>,
    actions: Vec<Action>,
    next_id: u64,
    shutdown: Option<Stage>,
    /// Every enabled service settled once: `boot complete` was logged.
    boot_complete: bool,
}

/// How far the shutdown went.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// The running services stop.
    Running,
    /// The services that ran run their `exec-stop`.
    ExecStop,
}

/// A service, as the engine tracks it.
struct Entry {
    /// Shared with the runs and the API's view.
    service: Arc<Service>,
    life: Life,
    status: ServiceStatus,
    /// The delay before the next restart.
    backoff: Duration,
    /// Failures in a row.
    crashes: u32,
    /// The next start is a restart by the policy (counted in `restarts`).
    restarting: bool,
    /// A socket-activated service is to start (a connection came, or it was asked for); cleared
    /// once its run is over for good.
    activated: bool,
    /// Its last run, which orders the `exec-stop` at shutdown.
    last_run: RunId,
}

/// Where a service is in its life cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Life {
    /// Not running, and started as soon as it may be; its state tells why not yet.
    Idle,
    /// Not running, by its own result: started again only on request or when its file changes.
    Settled,
    Running(Run),
    /// Waiting to be started again.
    Backoff {
        token: u64,
    },
    /// On request, or at shutdown.
    Stopped {
        /// Stopped at shutdown, its `exec-stop` left for once the remaining processes are gone.
        exec_stop_left: bool,
    },
}

/// A run in progress.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Run {
    id: RunId,
    phase: Phase,
    /// When `exec` started.
    started: Option<Instant>,
    /// Set once the run is being stopped.
    stopping: Option<Stopping>,
}

/// A run being stopped, and what becomes of its service then.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct Stopping {
    /// Its `exec-stop` is left for later (stopped at shutdown).
    exec_stop_left: bool,
    /// Stopped on request: it stays stopped.
    hold: bool,
    /// Its file is gone: it is forgotten.
    remove: bool,
}

/// What a running service runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Pre {
        /// A process that sent `READY=1` before `exec` was known to have started: ready then if
        /// it is `exec`'s.
        ready: Option<u32>,
    },
    Exec,
    Ready,
    Post,
    /// The `exec-stop` left for later at shutdown.
    Stop,
}

/// Whether an idle service may start.
enum Verdict {
    Start,
    /// It may not: the state to show, and why; and the socket-activated services it requires
    /// that are to start, when nothing else holds it back.
    Block {
        state: State,
        reason: String,
        demand: Vec<ServiceName>,
    },
}

impl Verdict {
    fn block(state: State, reason: String) -> Self {
        Self::Block {
            state,
            reason,
            demand: Vec::new(),
        }
    }
}

impl Entry {
    fn new(service: Service) -> Self {
        Self {
            service: Arc::new(service),
            life: Life::Idle,
            status: ServiceStatus::new(State::Waiting),
            backoff: FIRST_BACKOFF,
            crashes: 0,
            restarting: false,
            activated: false,
            last_run: 0,
        }
    }

    /// Shows `state` and `reason`.
    fn set(&mut self, state: State, reason: Option<String>) {
        if self.status.state != state {
            self.status = ServiceStatus {
                state,
                since: SystemTime::now(),
                ..self.status.clone()
            };
        }
        self.status.reason = reason;
    }

    /// Shows the state of a running service.
    fn show_running(&mut self) {
        if let Life::Running(run) = self.life {
            let state = match run.phase {
                _ if run.stopping.is_some() => State::Stopping,
                Phase::Pre { .. } => State::Starting,
                Phase::Exec => State::Running,
                Phase::Ready => State::Ready,
                Phase::Post | Phase::Stop => State::Stopping,
            };
            self.set(state, None);
        }
    }

    /// How its run is being stopped, if it is.
    fn stopping(&mut self) -> Option<&mut Stopping> {
        match &mut self.life {
            Life::Running(Run {
                stopping: Some(stopping),
                ..
            }) => Some(stopping),
            _ => None,
        }
    }

    /// Starts over: a restart asked for, or a new definition.
    fn reset(&mut self) {
        self.backoff = FIRST_BACKOFF;
        self.crashes = 0;
        self.restarting = false;
    }

    /// Stopped at shutdown, its `exec-stop` left for later.
    #[must_use]
    fn exec_stop_left(&self) -> bool {
        self.life
            == (Life::Stopped {
                exec_stop_left: true,
            })
    }

    /// Whether it is a socket-activated service waiting for a connection: not running nor to
    /// start.
    #[must_use]
    fn awaits_connection(&self) -> bool {
        self.service.socket_activated()
            && self.service.enabled
            && !self.activated
            && matches!(self.life, Life::Idle | Life::Settled)
    }

    /// Back to starting as soon as it may, unless it is to stay stopped.
    fn idle(&mut self) {
        if matches!(self.life, Life::Idle | Life::Settled | Life::Backoff { .. }) {
            self.life = Life::Idle;
        }
    }
}

/// Whether a service in `state` is done starting, one way or another.
#[must_use]
fn settled(state: State) -> bool {
    matches!(
        state,
        State::Ready | State::Exited | State::Failed | State::Inactive | State::Stopped
    )
}

/// Makes a socket-activated service start as soon as it may.
fn activate(entry: &mut Entry) {
    entry.activated = true;
    if entry.life == Life::Settled {
        entry.reset();
        entry.life = Life::Idle;
    }
}

/// Why the condition of `service` does not hold, if it does not.
#[must_use]
fn condition_failure(service: &Service, exists: impl Fn(&Path) -> bool) -> Option<String> {
    let path = service.condition.path_exists.as_ref()?;
    (!exists(path)).then(|| format!("condition: {} does not exist", path.display()))
}

/// Whether two definitions run the same: what serviced ignores (`meta`, `description`) aside.
#[must_use]
fn same(a: &Service, b: &Service) -> bool {
    let strip = |service: &Service| Service {
        description: String::new(),
        meta: Table::new(),
        ..service.clone()
    };
    strip(a) == strip(b)
}

impl Engine {
    /// An engine without services, checking conditions with `exists`.
    #[must_use]
    pub fn new(exists: impl Fn(&Path) -> bool + Send + Sync + 'static) -> Self {
        Self {
            entries: BTreeMap::new(),
            exists: Box::new(exists),
            cyclic: BTreeSet::new(),
            actions: Vec::new(),
            next_id: 1,
            shutdown: None,
            boot_complete: false,
        }
    }

    /// What to do, in order.
    #[must_use]
    pub fn take_actions(&mut self) -> Vec<Action> {
        std::mem::take(&mut self.actions)
    }

    /// The services, as they run (a removed service is kept until its run is over), and their
    /// status.
    pub fn services(&self) -> impl Iterator<Item = (&ServiceName, &Arc<Service>, &ServiceStatus)> {
        self.entries
            .iter()
            .map(|(name, entry)| (name, &entry.service, &entry.status))
    }

    /// Whether `service` is known.
    #[must_use]
    pub fn contains(&self, service: &ServiceName) -> bool {
        self.entries.contains_key(service)
    }

    /// The status of `service`, if it is known.
    #[cfg(test)]
    #[must_use]
    pub fn status(&self, service: &str) -> Option<&ServiceStatus> {
        self.entries.get(service).map(|entry| &entry.status)
    }

    /// Whether every run is over, after [`Engine::shutdown`]; after [`Engine::run_exec_stops`],
    /// every `exec-stop` too.
    #[must_use]
    pub fn stopped(&self) -> bool {
        !self.entries.values().any(|entry| self.to_stop(entry))
    }

    /// At shutdown, whether a service is still to stop: it runs, or its `exec-stop` is left and
    /// their turn came.
    #[must_use]
    fn to_stop(&self, entry: &Entry) -> bool {
        matches!(entry.life, Life::Running(_))
            || (self.shutdown == Some(Stage::ExecStop) && entry.exec_stop_left())
    }

    /// The socket-activated services whose sockets are to be watched for a connection: those
    /// waiting for one, whose condition holds (they have no socket otherwise).
    #[must_use]
    pub fn awaiting_connection(&self) -> Vec<ServiceName> {
        if self.shutdown.is_some() {
            return Vec::new();
        }
        self.entries
            .iter()
            .filter(|(name, entry)| {
                entry.awaits_connection() && !self.cyclic.contains(*name) && self.holds(entry)
            })
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// Whether the condition of `entry` holds.
    #[must_use]
    fn holds(&self, entry: &Entry) -> bool {
        condition_failure(&entry.service, &self.exists).is_none()
    }

    /// Takes the services as they are now: new ones start, removed ones stop and are forgotten,
    /// changed ones restart (or stop, when disabled).
    pub fn reload(&mut self, mut services: BTreeMap<ServiceName, Service>) {
        if self.shutdown.is_some() {
            return;
        }
        let names: Vec<ServiceName> = self.entries.keys().cloned().collect();
        for name in names {
            let service = services.remove(&name);
            let Some(entry) = self.entries.get_mut(&name) else {
                continue;
            };
            let Some(service) = service else {
                if entry.stopping().is_some_and(|stopping| stopping.remove) {
                    continue;
                }
                info!(service = %name, "service removed");
                match self.stop(&name) {
                    Some(stopping) => stopping.remove = true,
                    None => {
                        self.entries.remove(&name);
                    }
                }
                continue;
            };
            let was_removed = entry
                .stopping()
                .is_some_and(|stopping| std::mem::take(&mut stopping.remove));
            if same(&entry.service, &service) {
                continue;
            }
            if !was_removed {
                info!(service = %name, "service changed");
            }
            entry.reset();
            // Stopped as it was defined: its own exec-stop undoes what it did.
            let stopping = self.stop(&name).is_some();
            if let Some(entry) = self.entries.get_mut(&name) {
                if !stopping {
                    entry.idle();
                }
                entry.service = Arc::new(service);
            }
        }
        for (name, service) in services {
            info!(service = %name, "service added");
            self.entries.insert(name, Entry::new(service));
        }
        let cyclic = self.find_cycles();
        for name in cyclic.difference(&self.cyclic) {
            warn!(service = %name, "service on a dependency cycle");
        }
        self.cyclic = cyclic;
        self.settle();
    }

    /// The entry of `name`, unless the request about it is refused.
    fn requested(&mut self, name: &ServiceName) -> Result<&mut Entry, Refusal> {
        if self.shutdown.is_some() {
            return Err(Refusal::ShuttingDown);
        }
        self.entries.get_mut(name).ok_or(Refusal::Unknown)
    }

    /// Starts a stopped, exited or failed service once it may; a service being stopped on request
    /// starts again once stopped. Otherwise, it is starting or started already.
    pub fn start(&mut self, name: &ServiceName) -> Result<(), Refusal> {
        let entry = self.requested(name)?;
        info!(service = %name, "start requested");
        if let Some(stopping) = entry.stopping() {
            stopping.hold = false;
        }
        entry.activated = true;
        if matches!(entry.life, Life::Stopped { .. } | Life::Settled) {
            entry.reset();
            entry.life = Life::Idle;
        }
        self.settle();
        Ok(())
    }

    /// Stops a service; it stays stopped until started or restarted.
    pub fn stop_service(&mut self, name: &ServiceName) -> Result<(), Refusal> {
        let entry = self.requested(name)?;
        info!(service = %name, "stop requested");
        entry.activated = false;
        match self.stop(name) {
            Some(stopping) => stopping.hold = true,
            None => {
                if let Some(entry) = self.entries.get_mut(name) {
                    entry.life = Life::Stopped {
                        exec_stop_left: false,
                    };
                    entry.set(State::Stopped, None);
                }
            }
        }
        self.settle();
        Ok(())
    }

    /// Stops a service if it runs, then starts it again once it may; also from failed, exited or
    /// stopped.
    pub fn restart(&mut self, name: &ServiceName) -> Result<(), Refusal> {
        let entry = self.requested(name)?;
        info!(service = %name, "restart requested");
        entry.reset();
        if let Some(stopping) = entry.stopping() {
            stopping.hold = false;
        }
        entry.activated = true;
        // Nothing to wait for: it is not running, stopped or not.
        if self.stop(name).is_none()
            && let Some(entry) = self.entries.get_mut(name)
        {
            entry.life = Life::Idle;
        }
        self.settle();
        Ok(())
    }

    /// Stops the running services, dependents before what they depend on; starts nothing more.
    /// Every `exec-stop` is left to [`Engine::run_exec_stops`].
    pub fn shutdown(&mut self) {
        self.shutdown = Some(Stage::Running);
        for entry in self.entries.values_mut() {
            if matches!(entry.life, Life::Idle | Life::Backoff { .. }) {
                entry.life = Life::Stopped {
                    exec_stop_left: false,
                };
                entry.set(State::Stopped, None);
            }
        }
        self.settle();
    }

    /// Once the running services stopped and the remaining processes are gone: runs the
    /// `exec-stop` of the services stopped at shutdown, one at a time, the last started first.
    pub fn run_exec_stops(&mut self) {
        self.shutdown = Some(Stage::ExecStop);
        self.settle();
    }

    /// Takes into account what happened to a run, at `now`.
    pub fn handle(&mut self, event: Event, now: Instant) {
        match event {
            Event::Started { service, run, pid } => self.started(&service, run, pid, now),
            Event::Notified {
                service,
                pid,
                notification,
            } => self.notified(&service, pid, notification),
            Event::Exited { service, run, exit } => {
                if let Some(entry) = self.run_of(&service, run)
                    && let Life::Running(current) = &mut entry.life
                {
                    current.phase = Phase::Post;
                    let stopping = current.stopping.is_some();
                    entry.status.pid = None;
                    entry.status.last_exit = Some(exit);
                    entry.show_running();
                    if exit.success() || stopping {
                        info!(service = %service, %exit, "service exited");
                    } else {
                        warn!(service = %service, %exit, "service exited");
                    }
                }
            }
            Event::Finished {
                service,
                run,
                outcome,
            } => self.finished(&service, run, outcome, now),
            Event::BackoffElapsed { service, token } => {
                if let Some(entry) = self.entries.get_mut(&service)
                    && entry.life == (Life::Backoff { token })
                {
                    entry.life = Life::Idle;
                    entry.restarting = true;
                }
            }
            Event::Activated { service, socket } => self.activated(&service, &socket),
        }
        self.settle();
    }

    /// The entry of `service` if `run` is its current run.
    #[must_use]
    fn run_of(&mut self, service: &ServiceName, run: RunId) -> Option<&mut Entry> {
        let entry = self.entries.get_mut(service)?;
        match entry.life {
            Life::Running(current) if current.id == run => Some(entry),
            _ => None,
        }
    }

    /// A process of `service`, `pid`, sent `notification`: `READY=1` makes a `notify` service ready
    /// (a stale one, from a process of an older run, would find no running `exec`), `STATUS=`
    /// is kept until the next run.
    fn notified(&mut self, service: &ServiceName, pid: u32, notification: Notification) {
        let Some(entry) = self.entries.get_mut(service) else {
            return;
        };
        if let Some(text) = notification.status {
            entry.status.status_text = text;
        }
        if !notification.ready || !entry.service.notify {
            return;
        }
        match &mut entry.life {
            Life::Running(Run {
                phase: phase @ Phase::Exec,
                stopping: None,
                ..
            }) => {
                *phase = Phase::Ready;
                entry.show_running();
                info!(service = %service, "service ready");
            }
            // `exec` may notify before serviced hears of its start.
            Life::Running(Run {
                phase: Phase::Pre { ready },
                stopping: None,
                ..
            }) => *ready = Some(pid),
            _ => {}
        }
    }

    /// A connection waits on `socket` of `name`: it starts, if it waits for one.
    fn activated(&mut self, name: &ServiceName, socket: &SocketName) {
        if self.shutdown.is_some() {
            return;
        }
        let Some(entry) = self.entries.get_mut(name) else {
            return;
        };
        if !entry.awaits_connection() {
            return;
        }
        info!(service = %name, %socket, "connection to a socket, activating the service");
        activate(entry);
    }

    /// `exec` of run `run` started as `pid`.
    fn started(&mut self, service: &ServiceName, run: RunId, pid: u32, now: Instant) {
        let Some(entry) = self.run_of(service, run) else {
            return;
        };
        let Life::Running(current) = &mut entry.life else {
            return;
        };
        let early_ready = match current.phase {
            Phase::Pre { ready } => ready,
            _ => None,
        };
        let ready_now = !entry.service.notify || early_ready == Some(pid);
        current.phase = if ready_now { Phase::Ready } else { Phase::Exec };
        current.started = Some(now);
        entry.status.pid = Some(pid);
        entry.show_running();
        info!(service = %service, pid, "service started");
        if ready_now {
            info!(service = %service, "service ready");
        }
    }

    /// Run `run` is over: the service stops, restarts, or settles.
    fn finished(&mut self, service: &ServiceName, run: RunId, outcome: Outcome, now: Instant) {
        let shutting_down = self.shutdown.is_some();
        let Some(entry) = self.entries.get_mut(service) else {
            return;
        };
        let Life::Running(current) = entry.life else {
            return;
        };
        if current.id != run {
            return;
        }
        entry.status.pid = None;
        let ran_for = current
            .started
            .map(|started| now.saturating_duration_since(started));

        if current.stopping.is_some() || shutting_down {
            let stopping = current.stopping.unwrap_or_default();
            if stopping.remove {
                info!(service = %service, "service stopped and removed");
                self.entries.remove(service);
            } else if shutting_down {
                info!(service = %service, "service stopped");
                entry.life = Life::Stopped {
                    exec_stop_left: stopping.exec_stop_left,
                };
                entry.set(State::Stopped, None);
            } else if stopping.hold {
                info!(service = %service, "service stopped");
                entry.life = Life::Stopped {
                    exec_stop_left: false,
                };
                entry.activated = false;
                entry.set(State::Stopped, None);
            } else {
                info!(service = %service, "service stopped");
                entry.life = Life::Idle;
            }
            return;
        }

        if ran_for.is_some_and(|ran_for| ran_for >= HEALTHY_RUN) {
            entry.backoff = FIRST_BACKOFF;
            entry.crashes = 0;
        }
        let (success, reason, tail) = match outcome {
            Outcome::NotStarted { reason, tail } => (false, reason, tail),
            Outcome::Exited { exit, tail } => (exit.success(), exit.to_string(), tail),
        };
        if success {
            entry.crashes = 0;
        } else {
            entry.crashes += 1;
            if !entry.service.console && entry.crashes <= CRASHES_SHOWN && !tail.is_empty() {
                self.actions.push(Action::ShowCrash {
                    service: service.clone(),
                    lines: tail,
                });
            } else if !entry.service.console && entry.crashes == CRASHES_SHOWN + 1 {
                warn!(service = %service, "service keeps failing; its output stays in its log");
            }
        }

        let restart = match entry.service.restart {
            Restart::Always => true,
            Restart::OnFailure => !success,
            Restart::Never => false,
        };
        if restart {
            let delay = entry.backoff;
            entry.backoff = (delay * 2).min(MAX_BACKOFF);
            self.next_id += 1;
            let token = self.next_id;
            entry.life = Life::Backoff { token };
            entry.set(
                State::Backoff,
                Some(format!("{reason}; restarting in {}s", delay.as_secs())),
            );
            if success {
                info!(service = %service, delay = delay.as_secs(), "service restarting");
            } else {
                warn!(
                    service = %service,
                    reason,
                    delay = delay.as_secs(),
                    "service failed, restarting"
                );
            }
            self.actions.push(Action::Schedule {
                service: service.clone(),
                token,
                delay,
            });
        } else {
            entry.life = Life::Settled;
            // A socket-activated service waits for the next connection.
            entry.activated = false;
            if !success {
                warn!(service = %service, reason, "service failed");
                entry.set(State::Failed, Some(reason));
            } else {
                entry.set(State::Exited, None);
            }
        }
    }

    /// Stops a service: a running one is stopped (its run then runs its `exec-stop`), one whose
    /// `exec-stop` was left for later runs it. Returns how its run is being stopped, if there is
    /// one to wait for.
    fn stop(&mut self, name: &ServiceName) -> Option<&mut Stopping> {
        let first_stage = self.shutdown == Some(Stage::Running);
        let entry = self.entries.get_mut(name)?;
        if entry.stopping().is_some() {
            return entry.stopping();
        }
        match &mut entry.life {
            Life::Running(run) => {
                // At shutdown, its exec-stop waits for the remaining processes.
                let exec_stop_left = first_stage && !entry.service.exec_stop.is_empty();
                run.stopping = Some(Stopping {
                    exec_stop_left,
                    ..Stopping::default()
                });
                self.actions.push(Action::Stop {
                    service: name.clone(),
                    run: run.id,
                    exec_stop: !exec_stop_left,
                });
            }
            Life::Stopped {
                exec_stop_left: true,
            } => {
                self.next_id += 1;
                let run = self.next_id;
                entry.life = Life::Running(Run {
                    id: run,
                    phase: Phase::Stop,
                    started: None,
                    stopping: Some(Stopping::default()),
                });
                self.actions.push(Action::ExecStop {
                    service: name.clone(),
                    run,
                    definition: entry.service.clone(),
                });
            }
            _ => return None,
        }
        entry.show_running();
        info!(service = %name, "stopping service");
        entry.stopping()
    }

    /// Brings the services to where they may be: starts those that may start, explains why the
    /// others wait; or, at shutdown, stops what may be stopped. Then checks if boot completed.
    fn settle(&mut self) {
        if self.shutdown.is_some() {
            self.stop_next();
            return;
        }
        // An idle service's state depends on others': go on until nothing changes (the
        // dependencies without cycles, this ends).
        for _ in 0..=self.entries.len() {
            let mut changed = false;
            let names: Vec<ServiceName> = self.entries.keys().cloned().collect();
            for name in names {
                if self
                    .entries
                    .get(&name)
                    .is_none_or(|entry| entry.life != Life::Idle)
                {
                    continue;
                }
                match self.evaluate(&name) {
                    Verdict::Start => {
                        self.start_run(&name);
                        changed = true;
                    }
                    Verdict::Block {
                        state,
                        reason,
                        demand,
                    } => {
                        for required in demand {
                            info!(
                                service = %required,
                                by = %name,
                                "required by a service, activating the service"
                            );
                            if let Some(required) = self.entries.get_mut(&required) {
                                activate(required);
                                changed = true;
                            }
                        }
                        let Some(entry) = self.entries.get_mut(&name) else {
                            continue;
                        };
                        if entry.status.state != state
                            || entry.status.reason.as_ref() != Some(&reason)
                        {
                            debug!(service = %name, ?state, reason, "service not started");
                            entry.set(state, Some(reason));
                            changed = true;
                        }
                    }
                }
            }
            if !changed {
                break;
            }
        }
        self.check_boot_complete();
    }

    /// Whether an idle service may start, and if not why.
    #[must_use]
    fn evaluate(&self, name: &ServiceName) -> Verdict {
        let entry = &self.entries[name];
        let service = &entry.service;
        if !service.enabled {
            return Verdict::block(State::Inactive, "disabled".to_owned());
        }
        if self.cyclic.contains(name) {
            return Verdict::block(State::Failed, "dependency cycle".to_owned());
        }
        if service.socket_activated() && !entry.activated {
            let reason = match condition_failure(service, &self.exists) {
                Some(reason) => reason,
                None => "starts on its first connection".to_owned(),
            };
            return Verdict::block(State::Inactive, reason);
        }
        let mut failed = None;
        let mut inactive = None;
        let mut waiting = Vec::new();
        let mut demand = Vec::new();
        for required in &service.requires {
            let Some(other) = self.entries.get(required) else {
                failed.get_or_insert(format!("requires {required}, which does not exist"));
                continue;
            };
            // Socket-activated, it starts for this one.
            if other.status.state != State::Ready
                && other.awaits_connection()
                && !self.cyclic.contains(required)
                && self.holds(other)
            {
                demand.push(required.clone());
                waiting.push(required.as_str());
                continue;
            }
            let reason = match other.status.state {
                State::Ready => continue,
                State::Failed => format!("requires {required}, which failed"),
                State::Exited => format!("requires {required}, which exited"),
                State::Inactive => {
                    inactive.get_or_insert(format!("requires {required}, which is inactive"));
                    continue;
                }
                _ => {
                    waiting.push(required.as_str());
                    continue;
                }
            };
            failed.get_or_insert(reason);
        }
        if let Some(reason) = failed {
            return Verdict::block(State::Failed, reason);
        }
        if let Some(reason) = inactive {
            return Verdict::block(State::Inactive, reason);
        }
        let reason = format!("waiting for {}", waiting.join(", "));
        if waiting.len() > demand.len() {
            return Verdict::block(State::Waiting, reason);
        }
        if let Some(reason) = condition_failure(service, &self.exists) {
            return Verdict::block(State::Inactive, reason);
        }
        if !demand.is_empty() {
            return Verdict::Block {
                state: State::Waiting,
                reason,
                demand,
            };
        }
        Verdict::Start
    }

    /// Starts a new run of `name`.
    fn start_run(&mut self, name: &ServiceName) {
        let Some(entry) = self.entries.get_mut(name) else {
            return;
        };
        self.next_id += 1;
        let run = self.next_id;
        entry.life = Life::Running(Run {
            id: run,
            phase: Phase::Pre { ready: None },
            started: None,
            stopping: None,
        });
        entry.last_run = run;
        if std::mem::take(&mut entry.restarting) {
            entry.status.restarts += 1;
        }
        entry.status.pid = None;
        entry.status.status_text.clear();
        entry.show_running();
        debug!(service = %name, run, "starting service");
        self.actions.push(Action::Start {
            service: name.clone(),
            run,
            definition: entry.service.clone(),
        });
    }

    /// At shutdown: stops the running services that no other one to stop requires; then runs the
    /// `exec-stop` left, one at a time, the last started first.
    fn stop_next(&mut self) {
        let pending: Vec<ServiceName> = self
            .entries
            .iter()
            .filter(|(_, entry)| self.to_stop(entry))
            .map(|(name, _)| name.clone())
            .collect();
        if self.shutdown == Some(Stage::ExecStop) {
            let busy = pending
                .iter()
                .any(|name| matches!(self.entries[name].life, Life::Running(_)));
            let last = pending
                .iter()
                .max_by_key(|name| self.entries[*name].last_run)
                .cloned();
            if let Some(name) = last
                && !busy
            {
                self.stop(&name);
            }
            return;
        }
        let mut stoppable = Vec::new();
        let mut any_stopping = false;
        for name in &pending {
            if let Life::Running(Run {
                stopping: Some(_), ..
            }) = self.entries[name].life
            {
                any_stopping = true;
                continue;
            }
            let needed = pending.iter().any(|other| {
                let service = &self.entries[other].service;
                other != name && service.requires.contains(name)
            });
            if !needed {
                stoppable.push(name.clone());
            }
        }
        if stoppable.is_empty() && !any_stopping {
            // Only a cycle is left: everything at once.
            stoppable = pending;
        }
        for name in stoppable {
            self.stop(&name);
        }
    }

    /// Logs `boot complete` the first time every enabled service settled. The supervisor reads the
    /// service files again before handling what may settle a service, so the services one wrote
    /// before it got ready or ended (machine-controller enables those user-data asks for) are
    /// known by then and keep boot from being complete.
    fn check_boot_complete(&mut self) {
        if self.boot_complete {
            return;
        }
        let all = self
            .entries
            .values()
            .filter(|entry| entry.service.enabled)
            .all(|entry| settled(entry.status.state));
        if all {
            self.boot_complete = true;
            info!("boot complete");
        }
    }

    /// The enabled services that require themselves through other enabled services.
    #[must_use]
    fn find_cycles(&self) -> BTreeSet<ServiceName> {
        let edges = |name: &ServiceName| -> Vec<&ServiceName> {
            let service = &self.entries[name].service;
            service
                .requires
                .iter()
                .filter(|dep| {
                    self.entries
                        .get(*dep)
                        .is_some_and(|entry| entry.service.enabled)
                })
                .collect()
        };
        let mut cyclic = BTreeSet::new();
        for (name, entry) in &self.entries {
            if !entry.service.enabled {
                continue;
            }
            let mut seen = BTreeSet::new();
            let mut stack = edges(name);
            while let Some(next) = stack.pop() {
                if next == name {
                    cyclic.insert(name.clone());
                    break;
                }
                if seen.insert(next) {
                    stack.extend(edges(next));
                }
            }
        }
        cyclic
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use super::*;

    fn service(text: &str) -> Service {
        toml::from_str(text).unwrap()
    }

    fn name(name: &str) -> ServiceName {
        name.parse().unwrap()
    }

    fn services(list: &[(&str, &str)]) -> BTreeMap<ServiceName, Service> {
        list.iter()
            .map(|(n, text)| (name(n), service(text)))
            .collect()
    }

    /// An engine, the paths that exist for it, and a clock.
    struct Harness {
        engine: Engine,
        paths: Arc<Mutex<HashSet<PathBuf>>>,
        now: Instant,
    }

    impl Harness {
        fn new() -> Self {
            let paths = Arc::new(Mutex::new(HashSet::new()));
            let probe = paths.clone();
            Self {
                engine: Engine::new(move |path| probe.lock().unwrap().contains(path)),
                paths,
                now: Instant::now(),
            }
        }

        fn state(&self, service: &str) -> State {
            self.engine.status(service).unwrap().state
        }

        fn reason(&self, service: &str) -> String {
            self.engine
                .status(service)
                .unwrap()
                .reason
                .clone()
                .unwrap_or_default()
        }

        /// The services started since last asked, with their runs.
        fn started(&mut self) -> Vec<(String, RunId)> {
            let mut started = Vec::new();
            for action in self.engine.take_actions() {
                if let Action::Start { service, run, .. } = action {
                    started.push((service.to_string(), run));
                }
            }
            started
        }

        fn event(&mut self, event: Event) {
            self.engine.handle(event, self.now);
        }

        fn run_started(&mut self, service: &str, run: RunId) {
            self.event(Event::Started {
                service: name(service),
                run,
                pid: 100,
            });
        }

        fn notify(&mut self, service: &str, pid: u32, datagram: &[u8]) {
            self.event(Event::Notified {
                service: name(service),
                pid,
                notification: Notification::parse(datagram),
            });
        }

        fn run_finished(&mut self, service: &str, run: RunId, exit: Exit) {
            self.event(Event::Exited {
                service: name(service),
                run,
                exit,
            });
            self.event(Event::Finished {
                service: name(service),
                run,
                outcome: Outcome::Exited {
                    exit,
                    tail: vec!["last words".into()],
                },
            });
        }

        /// Starts a service and makes it ready.
        fn ready(&mut self, service: &str, run: RunId) {
            self.run_started(service, run);
            self.notify(service, 100, b"READY=1");
        }

        /// Ends a run of `exec-stop` alone.
        fn undone(&mut self, service: &str, run: RunId) {
            self.event(Event::Finished {
                service: name(service),
                run,
                outcome: Outcome::NotStarted {
                    reason: "stopped".into(),
                    tail: vec![],
                },
            });
        }

        /// The services stopped and the `exec-stop` runs since last asked, sorted; starts
        /// forbidden.
        fn stops(&mut self) -> (Vec<String>, Vec<(String, RunId)>) {
            let (mut stops, mut undos) = (Vec::new(), Vec::new());
            for action in self.engine.take_actions() {
                match action {
                    Action::Stop { service, .. } => stops.push(service.to_string()),
                    Action::ExecStop { service, run, .. } => undos.push((service.to_string(), run)),
                    Action::Start { service, .. } => panic!("{service} started"),
                    _ => {}
                }
            }
            stops.sort();
            undos.sort();
            (stops, undos)
        }
    }

    const NET: &str = "exec = [\"/usr/bin/network-controller\"]\nnotify = true\n";
    const SETUP: &str = "exec = [\"/usr/bin/setup\"]\n\
        requires = [\"network-controller\"]\n\
        notify = true\n";
    const CONTAINERD: &str = "exec = [\"/usr/bin/containerd\"]\nrequires = [\"setup\"]\n";

    #[test]
    fn starts_in_dependency_order() {
        let mut h = Harness::new();
        h.engine.reload(services(&[
            ("network-controller", NET),
            ("setup", SETUP),
            ("containerd", CONTAINERD),
        ]));
        let started = h.started();
        assert_eq!(started.len(), 1);
        let (_, net) = started[0].clone();
        assert_eq!(h.state("network-controller"), State::Starting);
        assert_eq!(h.state("setup"), State::Waiting);
        assert_eq!(h.reason("setup"), "waiting for network-controller");
        assert_eq!(h.state("containerd"), State::Waiting);

        h.run_started("network-controller", net);
        assert_eq!(
            h.state("network-controller"),
            State::Running,
            "until it notifies READY=1"
        );
        h.notify("network-controller", 100, b"STATUS=leasing");
        assert_eq!(h.state("network-controller"), State::Running);
        assert_eq!(
            h.engine.status("network-controller").unwrap().status_text,
            "leasing"
        );
        assert!(h.started().is_empty());
        h.notify("network-controller", 100, b"READY=1");
        assert_eq!(h.state("network-controller"), State::Ready);
        let started = h.started();
        assert_eq!(started[0].0, "setup");

        h.run_started("setup", started[0].1);
        assert_eq!(h.state("setup"), State::Running);
        assert!(h.started().is_empty());
        h.notify("setup", 100, b"READY=1");
        assert_eq!(h.state("setup"), State::Ready);
        let started = h.started();
        assert_eq!(started[0].0, "containerd");
        h.run_started("containerd", started[0].1);
        assert_eq!(
            h.state("containerd"),
            State::Ready,
            "a daemon without notify"
        );
    }

    #[test]
    fn failures_propagate_to_dependents() {
        let mut h = Harness::new();
        h.engine.reload(services(&[
            (
                "network-controller",
                "exec = [\"/usr/bin/network-controller\"]\n",
            ),
            ("setup", &format!("{SETUP}restart = \"never\"\n")),
            ("containerd", CONTAINERD),
            (
                "kubelet",
                "exec = [\"/usr/bin/kubelet\"]\nrequires = [\"containerd\"]\n",
            ),
            (
                "orphan",
                "exec = [\"/usr/bin/x\"]\nrequires = [\"missing\"]\n",
            ),
            ("off", "enabled = false\nexec = [\"/usr/bin/x\"]\n"),
            (
                "needs-off",
                "exec = [\"/usr/bin/x\"]\nrequires = [\"off\"]\n",
            ),
        ]));
        let net = h.started()[0].1;
        h.run_started("network-controller", net);
        let setup = h.started()[0].1;
        h.run_started("setup", setup);
        h.run_finished("setup", setup, Exit::Code(1));
        assert_eq!(h.state("setup"), State::Failed);
        assert_eq!(h.reason("setup"), "exit code 1");
        assert_eq!(h.state("containerd"), State::Failed);
        assert_eq!(h.reason("containerd"), "requires setup, which failed");
        assert_eq!(h.state("kubelet"), State::Failed);
        assert_eq!(h.reason("kubelet"), "requires containerd, which failed");
        assert_eq!(h.reason("orphan"), "requires missing, which does not exist");
        assert_eq!(h.state("off"), State::Inactive);
        assert_eq!(h.state("needs-off"), State::Inactive);
        assert!(h.started().is_empty());

        // Restarted on request, it unblocks its dependents.
        h.engine.restart(&name("setup")).unwrap();
        let started = h.started();
        assert_eq!(started[0].0, "setup");
        assert_eq!(h.state("containerd"), State::Waiting);
        h.ready("setup", started[0].1);
        assert_eq!(h.started()[0].0, "containerd");
    }

    #[test]
    fn conditions_make_services_inactive() {
        let mut h = Harness::new();
        let attest = "exec = [\"/usr/bin/a\"]\ncondition.path-exists = \"/dev/tpmrm0\"\n";
        h.engine.reload(services(&[("trust-controller", attest)]));
        assert!(h.started().is_empty());
        assert_eq!(h.state("trust-controller"), State::Inactive);
        assert_eq!(
            h.reason("trust-controller"),
            "condition: /dev/tpmrm0 does not exist"
        );

        h.paths.lock().unwrap().insert(PathBuf::from("/dev/tpmrm0"));
        h.engine.reload(services(&[("trust-controller", attest)]));
        assert_eq!(h.started().len(), 1, "checked again at every change");
    }

    #[test]
    fn exec_pre_failure_and_restart_backoff() {
        let mut h = Harness::new();
        h.engine.reload(services(&[(
            "web",
            "exec = [\"/usr/bin/ctr\"]\nexec-pre = [[\"/usr/bin/ctr\", \"version\"]]\n",
        )]));
        let mut delays = Vec::new();
        for _ in 0..8 {
            let run = h.started()[0].1;
            h.event(Event::Finished {
                service: name("web"),
                run,
                outcome: Outcome::NotStarted {
                    reason: "exec-pre /usr/bin/ctr: exit code 1".into(),
                    tail: vec![],
                },
            });
            assert_eq!(h.state("web"), State::Backoff);
            let Some(Action::Schedule { token, delay, .. }) = h.engine.take_actions().pop() else {
                panic!("a restart is scheduled");
            };
            delays.push(delay.as_secs());
            h.event(Event::BackoffElapsed {
                service: name("web"),
                token,
            });
        }
        assert_eq!(delays, [1, 2, 4, 8, 16, 32, 60, 60]);
        assert_eq!(h.engine.status("web").unwrap().restarts, 8);

        // A healthy run starts the backoff over.
        let run = h.started()[0].1;
        h.run_started("web", run);
        h.now += HEALTHY_RUN;
        h.run_finished("web", run, Exit::Signal(9));
        let actions = h.engine.take_actions();
        assert!(
            matches!(actions[0], Action::ShowCrash { .. }),
            "{actions:?}"
        );
        assert!(
            matches!(actions[1], Action::Schedule { delay, .. } if delay == FIRST_BACKOFF),
            "{actions:?}"
        );

        // A stale timer is ignored.
        h.event(Event::BackoffElapsed {
            service: name("web"),
            token: 1,
        });
        assert_eq!(h.state("web"), State::Backoff);
    }

    #[test]
    fn restart_policies() {
        let mut h = Harness::new();
        h.engine.reload(services(&[
            ("job", "exec = [\"/usr/bin/x\"]\nrestart = \"never\"\n"),
            (
                "retry",
                "exec = [\"/usr/bin/x\"]\nrestart = \"on-failure\"\n",
            ),
            (
                "done",
                "exec = [\"/usr/bin/x\"]\nrestart = \"on-failure\"\n",
            ),
            ("daemon", "exec = [\"/usr/bin/x\"]\n"),
        ]));
        let started: BTreeMap<String, RunId> = h.started().into_iter().collect();
        h.run_started("job", started["job"]);
        h.run_finished("job", started["job"], Exit::Code(3));
        assert_eq!(h.state("job"), State::Failed);
        h.run_started("retry", started["retry"]);
        h.run_finished("retry", started["retry"], Exit::Code(3));
        assert_eq!(h.state("retry"), State::Backoff);
        h.run_started("done", started["done"]);
        h.run_finished("done", started["done"], Exit::Code(0));
        assert_eq!(h.state("done"), State::Exited);
        assert_eq!(
            h.engine.status("done").unwrap().last_exit,
            Some(Exit::Code(0))
        );
        h.run_started("daemon", started["daemon"]);
        h.run_finished("daemon", started["daemon"], Exit::Code(0));
        assert_eq!(h.state("daemon"), State::Backoff, "always, by default");
    }

    #[test]
    fn crash_tails_are_shown_three_times_in_a_row() {
        let mut h = Harness::new();
        h.engine.reload(services(&[
            ("quiet", "exec = [\"/usr/bin/x\"]\n"),
            ("loud", "exec = [\"/usr/bin/x\"]\nconsole = true\n"),
        ]));
        let mut shown = BTreeMap::<String, usize>::new();
        for _ in 0..5 {
            for (service, run) in h.started() {
                h.run_started(&service, run);
                h.run_finished(&service, run, Exit::Code(1));
            }
            for action in h.engine.take_actions() {
                match action {
                    Action::ShowCrash { service, lines } => {
                        assert_eq!(lines, ["last words"]);
                        *shown.entry(service.to_string()).or_default() += 1;
                    }
                    Action::Schedule { service, token, .. } => {
                        h.event(Event::BackoffElapsed { service, token })
                    }
                    _ => {}
                }
            }
        }
        assert_eq!(
            shown,
            BTreeMap::from([(String::from("quiet"), 3)]),
            "console services are on the console"
        );
    }

    #[test]
    fn reload_applies_differences() {
        let mut h = Harness::new();
        let a = "exec = [\"/usr/bin/a\"]\n";
        h.engine
            .reload(services(&[("a", a), ("b", a), ("c", a), ("d", a)]));
        let runs: BTreeMap<String, RunId> = h.started().into_iter().collect();
        for (service, run) in &runs {
            h.run_started(service, *run);
        }
        h.engine.reload(services(&[
            (
                "a",
                "exec = [\"/usr/bin/a\"]\n\
                 description = \"only described\"\n\
                 meta.owner = \"api\"\n",
            ),
            ("b", "exec = [\"/usr/bin/a\", \"--new\"]\n"),
            ("c", "exec = [\"/usr/bin/a\"]\nenabled = false\n"),
            ("e", a),
        ]));
        let actions = h.engine.take_actions();
        let stopped: Vec<&str> = actions
            .iter()
            .filter_map(|action| match action {
                Action::Stop { service, .. } => Some(service.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(stopped, ["b", "c", "d"], "a is unchanged for serviced");
        assert!(matches!(&actions[3], Action::Start { service, .. } if service.as_str() == "e"));
        assert_eq!(h.state("d"), State::Stopping);

        for service in ["b", "c", "d"] {
            h.event(Event::Finished {
                service: name(service),
                run: runs[service],
                outcome: Outcome::Exited {
                    exit: Exit::Signal(15),
                    tail: vec![],
                },
            });
        }
        let started = h.started();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].0, "b", "restarted with its new definition");
        assert_eq!(h.state("c"), State::Inactive);
        assert!(h.engine.status("d").is_none(), "forgotten once stopped");
    }

    #[test]
    fn restart_requests() {
        let mut h = Harness::new();
        h.engine
            .reload(services(&[("a", "exec = [\"/usr/bin/a\"]\n")]));
        let run = h.started()[0].1;
        h.run_started("a", run);
        h.engine.restart(&name("a")).unwrap();
        assert!(matches!(h.engine.take_actions()[..], [Action::Stop { run: r, .. }] if r == run));
        h.run_finished("a", run, Exit::Signal(15));
        assert_eq!(h.started().len(), 1);
        assert_eq!(
            h.engine.status("a").unwrap().restarts,
            0,
            "only the policy's restarts count"
        );
        assert_eq!(h.engine.restart(&name("unknown")), Err(Refusal::Unknown));
        assert!(h.engine.take_actions().is_empty());
    }

    #[test]
    fn dependency_cycles_fail() {
        let mut h = Harness::new();
        h.engine.reload(services(&[
            ("a", "exec = [\"/usr/bin/a\"]\nrequires = [\"b\"]\n"),
            ("b", "exec = [\"/usr/bin/a\"]\nrequires = [\"a\"]\n"),
            ("c", "exec = [\"/usr/bin/a\"]\nrequires = [\"a\"]\n"),
        ]));
        assert_eq!(h.reason("a"), "dependency cycle");
        assert_eq!(h.reason("b"), "dependency cycle");
        assert_eq!(h.reason("c"), "requires a, which failed");
    }

    #[test]
    fn boot_completes_once_everything_settled() {
        let mut h = Harness::new();
        let image = [("network-controller", NET), ("setup", SETUP)];
        h.engine.reload(services(&image));
        assert!(!h.engine.boot_complete);
        let net = h.started()[0].1;
        h.run_started("network-controller", net);
        h.notify("network-controller", 100, b"READY=1");
        assert!(!h.engine.boot_complete, "setup is starting");
        let setup = h.started()[0].1;
        h.run_started("setup", setup);

        // setup writes a service, then gets ready: the supervisor reads the services again before
        // handling its READY=1, so the new service is waiting when it settles.
        let workload = "exec = [\"/usr/bin/ctr\"]\nrequires = [\"setup\"]\nnotify = true\n";
        let mut written = services(&image);
        written.insert(name("workload-web"), service(workload));
        written.insert(
            name("off"),
            service("enabled = false\nexec = [\"/usr/bin/x\"]\n"),
        );
        h.engine.reload(written);
        assert!(!h.engine.boot_complete);
        h.notify("setup", 100, b"READY=1");
        assert_eq!(h.state("setup"), State::Ready);
        assert!(!h.engine.boot_complete, "workload-web is starting");
        let web = h.started()[0].1;
        h.run_started("workload-web", web);
        assert!(!h.engine.boot_complete, "workload-web is not ready");
        h.notify("workload-web", 100, b"READY=1");
        assert!(h.engine.boot_complete, "disabled services do not count");
    }

    #[test]
    fn notifications_before_the_start_is_known() {
        let mut h = Harness::new();
        h.engine.reload(services(&[("network-controller", NET)]));
        let run = h.started()[0].1;
        h.notify("network-controller", 7, b"READY=1");
        assert_eq!(h.state("network-controller"), State::Starting);
        h.run_started("network-controller", run);
        assert_eq!(
            h.state("network-controller"),
            State::Running,
            "READY=1 came from another process (an exec-pre)"
        );

        h.engine.restart(&name("network-controller")).unwrap();
        h.run_finished("network-controller", run, Exit::Signal(15));
        let run = h.started()[0].1;
        h.notify("network-controller", 100, b"READY=1\nSTATUS=leased");
        h.run_started("network-controller", run);
        assert_eq!(
            h.state("network-controller"),
            State::Ready,
            "exec's own READY=1"
        );
        assert_eq!(
            h.engine.status("network-controller").unwrap().status_text,
            "leased"
        );
    }

    #[test]
    fn stopped_services_stay_stopped_until_started() {
        let mut h = Harness::new();
        let needs_web = "exec = [\"/usr/bin/x\"]\nrequires = [\"web\"]\n";
        h.engine.reload(services(&[
            ("web", "exec = [\"/usr/bin/web\"]\nnotify = true\n"),
            ("job", "exec = [\"/usr/bin/x\"]\nrestart = \"never\"\n"),
        ]));
        let runs: BTreeMap<String, RunId> = h.started().into_iter().collect();
        h.run_started("web", runs["web"]);
        h.run_started("job", runs["job"]);
        h.run_finished("job", runs["job"], Exit::Code(1));
        assert_eq!(h.state("job"), State::Failed);
        assert!(!h.engine.boot_complete, "web is not ready");
        let _ = h.engine.take_actions();

        h.engine.stop_service(&name("web")).unwrap();
        assert!(matches!(h.engine.take_actions()[..], [Action::Stop { .. }]));
        assert_eq!(h.state("web"), State::Stopping);
        h.run_finished("web", runs["web"], Exit::Signal(15));
        assert_eq!(h.state("web"), State::Stopped);
        assert!(h.started().is_empty(), "not restarted by its policy");
        assert!(h.engine.boot_complete, "a stopped service is settled");

        // Nor by a change of its file; a service requiring it waits.
        h.engine.reload(services(&[
            (
                "web",
                "exec = [\"/usr/bin/web\", \"--new\"]\nnotify = true\n",
            ),
            ("job", "exec = [\"/usr/bin/x\"]\nrestart = \"never\"\n"),
            ("needs-web", needs_web),
        ]));
        assert!(h.started().is_empty());
        assert_eq!(h.state("web"), State::Stopped);
        assert_eq!(h.reason("needs-web"), "waiting for web");

        h.engine.stop_service(&name("job")).unwrap();
        assert_eq!(h.state("job"), State::Stopped, "nothing to stop");
        h.engine.start(&name("job")).unwrap();
        assert_eq!(h.started()[0].0, "job");

        h.engine.start(&name("web")).unwrap();
        let web = h.started()[0].1;
        h.run_started("web", web);
        h.notify("web", 100, b"READY=1");
        assert_eq!(h.started()[0].0, "needs-web");
        h.engine.start(&name("web")).unwrap();
        assert!(h.engine.take_actions().is_empty(), "started already");

        // Restarted from stopped.
        h.engine.stop_service(&name("web")).unwrap();
        h.run_finished("web", web, Exit::Signal(15));
        h.engine.restart(&name("web")).unwrap();
        assert_eq!(h.started()[0].0, "web");

        h.engine.shutdown();
        assert_eq!(h.engine.start(&name("web")), Err(Refusal::ShuttingDown));
        assert_eq!(
            h.engine.stop_service(&name("x")),
            Err(Refusal::ShuttingDown)
        );
    }

    const VOLUME: &str = "exec = [\"/usr/bin/volume\"]\n\
        exec-stop = [[\"/usr/bin/volume\", \"stop\"]]\n";

    #[test]
    fn shutdown_runs_every_exec_stop_last_in_reverse_start_order() {
        let mut h = Harness::new();
        let controller = "exec = [\"/usr/bin/setup\"]\n\
            requires = [\"volume\"]\n\
            exec-stop = [[\"/usr/bin/setup\", \"stop\"]]\n";
        let late = "exec = [\"/usr/bin/late\"]\n\
            exec-stop = [[\"/usr/bin/late\", \"stop\"]]\n";
        let kubelet = "exec = [\"/usr/bin/kubelet\"]\n\
            requires = [\"containerd\"]\n\
            exec-stop = [[\"/usr/bin/kubelet\", \"stop\"]]\n";
        h.engine.reload(services(&[
            ("volume", VOLUME),
            ("setup", controller),
            ("containerd", CONTAINERD),
            ("kubelet", kubelet),
            ("plain", "exec = [\"/usr/bin/x\"]\n"),
            ("late", late),
        ]));
        let mut runs = BTreeMap::new();
        let mut order = Vec::new();
        loop {
            let started = h.started();
            if started.is_empty() {
                break;
            }
            for (service, run) in started {
                h.run_started(&service, run);
                order.push(service.clone());
                runs.insert(service, run);
            }
        }
        assert_eq!(
            order,
            ["late", "plain", "volume", "setup", "containerd", "kubelet"]
        );

        // The running services stop, dependents first; their exec-stop is left for later.
        h.engine.shutdown();
        let stop_actions = |h: &mut Harness| -> Vec<(String, bool)> {
            let mut stops: Vec<(String, bool)> = h
                .engine
                .take_actions()
                .into_iter()
                .map(|action| match action {
                    Action::Stop {
                        service, exec_stop, ..
                    } => (service.to_string(), exec_stop),
                    _ => panic!("{action:?}"),
                })
                .collect();
            stops.sort();
            stops
        };
        assert_eq!(
            stop_actions(&mut h),
            [
                ("kubelet".into(), false),
                ("late".into(), false),
                ("plain".into(), true)
            ]
        );
        for service in ["kubelet", "late", "plain"] {
            h.run_finished(service, runs[service], Exit::Signal(15));
        }
        assert_eq!(
            stop_actions(&mut h),
            [("containerd".into(), true)],
            "nothing to leave for later"
        );
        h.run_finished("containerd", runs["containerd"], Exit::Signal(15));
        assert_eq!(stop_actions(&mut h), [("setup".into(), false)]);
        h.run_finished("setup", runs["setup"], Exit::Signal(15));
        assert_eq!(stop_actions(&mut h), [("volume".into(), false)]);
        h.run_finished("volume", runs["volume"], Exit::Signal(15));
        assert_eq!(h.state("late"), State::Stopped);
        assert_eq!(h.stops(), (vec![], vec![]), "exec-stop waits");
        assert!(h.engine.stopped());

        // Then one at a time, the last started first: volume's after those of the services
        // started after it.
        h.engine.run_exec_stops();
        let mut undone = Vec::new();
        loop {
            let (stops, undos) = h.stops();
            assert!(stops.is_empty());
            let [(service, run)] = &undos[..] else {
                assert!(undos.is_empty(), "one at a time: {undos:?}");
                break;
            };
            assert!(!h.engine.stopped());
            assert_eq!(h.state(service), State::Stopping);
            h.undone(service, *run);
            assert_eq!(h.state(service), State::Stopped);
            undone.push(service.clone());
        }
        assert_eq!(undone, ["kubelet", "setup", "volume", "late"]);
        assert!(h.engine.stopped());
    }

    const TRUST: &str = "exec = [\"/usr/bin/trust-controller\"]\n\
        condition.path-exists = \"/dev/tpmrm0\"\n\
        [[sockets]]\n\
        name = \"api\"\n\
        path = \"/run/trust-controller/api.sock\"\n\
        activate = true\n";

    #[test]
    fn connections_activate_socket_services() {
        let mut h = Harness::new();
        h.engine.reload(services(&[("trust-controller", TRUST)]));
        assert!(h.started().is_empty());
        assert_eq!(h.state("trust-controller"), State::Inactive);
        assert_eq!(
            h.reason("trust-controller"),
            "condition: /dev/tpmrm0 does not exist"
        );
        assert!(h.engine.awaiting_connection().is_empty(), "no socket");

        h.paths.lock().unwrap().insert(PathBuf::from("/dev/tpmrm0"));
        h.engine.reload(services(&[("trust-controller", TRUST)]));
        assert!(h.started().is_empty(), "not at boot");
        assert_eq!(h.state("trust-controller"), State::Inactive);
        assert_eq!(
            h.reason("trust-controller"),
            "starts on its first connection"
        );
        assert!(
            h.engine.boot_complete,
            "waiting for a connection is settled"
        );
        assert_eq!(h.engine.awaiting_connection(), [name("trust-controller")]);

        let activated = |h: &mut Harness| {
            h.event(Event::Activated {
                service: name("trust-controller"),
                socket: "api".parse().unwrap(),
            });
        };
        activated(&mut h);
        let run = h.started()[0].1;
        assert!(
            h.engine.awaiting_connection().is_empty(),
            "it has the sockets"
        );
        activated(&mut h);
        assert!(h.started().is_empty(), "started once");
        h.run_started("trust-controller", run);
        assert_eq!(h.state("trust-controller"), State::Ready);

        // A crash restarts it by its policy, without a connection.
        h.run_finished("trust-controller", run, Exit::Code(1));
        assert_eq!(h.state("trust-controller"), State::Backoff);
        assert!(h.engine.awaiting_connection().is_empty());
        let Some(Action::Schedule { token, .. }) = h.engine.take_actions().pop() else {
            panic!("a restart is scheduled");
        };
        h.event(Event::BackoffElapsed {
            service: name("trust-controller"),
            token,
        });
        let run = h.started()[0].1;
        h.run_started("trust-controller", run);

        // Exited and not restarted: the next connection starts it again.
        let on_failure = format!("restart = \"on-failure\"\n{TRUST}");
        h.engine
            .reload(services(&[("trust-controller", &on_failure)]));
        h.run_finished("trust-controller", run, Exit::Signal(15));
        let run = h.started()[0].1;
        h.run_started("trust-controller", run);
        h.run_finished("trust-controller", run, Exit::Code(0));
        assert_eq!(h.state("trust-controller"), State::Exited);
        assert_eq!(h.engine.awaiting_connection(), [name("trust-controller")]);
        activated(&mut h);
        assert_eq!(h.started().len(), 1);
    }

    #[test]
    fn requirements_activate_socket_services() {
        let mut h = Harness::new();
        let storage = "exec = [\"/usr/bin/storage-controller\"]\n\
            notify = true\n\
            [[sockets]]\n\
            name = \"api\"\n\
            path = \"/run/storage-controller/api.sock\"\n\
            activate = true\n";
        let containerd = "exec = [\"/usr/bin/containerd\"]\n\
            requires = [\"setup\", \"storage-controller\"]\n";
        let controller = "exec = [\"/usr/bin/setup\"]\nnotify = true\n";
        h.engine.reload(services(&[
            ("storage-controller", storage),
            ("containerd", containerd),
            ("setup", controller),
        ]));
        let started = h.started();
        assert_eq!(started.len(), 1);
        assert_eq!(started[0].0, "setup");
        assert_eq!(
            h.state("storage-controller"),
            State::Inactive,
            "not activated while containerd waits for something else"
        );
        assert_eq!(
            h.reason("containerd"),
            "waiting for setup, storage-controller"
        );

        h.run_started("setup", started[0].1);
        h.notify("setup", 100, b"READY=1");
        let started = h.started();
        assert_eq!(
            started[0].0, "storage-controller",
            "activated by containerd"
        );
        assert_eq!(h.reason("containerd"), "waiting for storage-controller");
        h.run_started("storage-controller", started[0].1);
        assert!(
            h.started().is_empty(),
            "storage-controller is not ready yet"
        );
        h.notify("storage-controller", 100, b"READY=1");
        assert_eq!(h.started()[0].0, "containerd");

        // Started on request too.
        let mut h = Harness::new();
        h.engine
            .reload(services(&[("storage-controller", storage)]));
        assert!(h.started().is_empty());
        h.engine.start(&name("storage-controller")).unwrap();
        assert_eq!(h.started().len(), 1);
    }

    #[test]
    fn shutdown_stops_dependents_first() {
        let mut h = Harness::new();
        h.engine.reload(services(&[
            (
                "network-controller",
                "exec = [\"/usr/bin/network-controller\"]\n",
            ),
            (
                "setup",
                "exec = [\"/usr/bin/setup\"]\nrequires = [\"network-controller\"]\n",
            ),
            ("containerd", CONTAINERD),
            (
                "time-controller",
                "exec = [\"/usr/bin/time-controller\"]\nrequires = [\"setup\"]\n",
            ),
            (
                "workload-web",
                "exec = [\"/usr/bin/ctr\"]\nrequires = [\"containerd\"]\n",
            ),
            (
                "pending",
                "exec = [\"/usr/bin/x\"]\nrequires = [\"missing-later\"]\n",
            ),
        ]));
        let mut runs = BTreeMap::new();
        loop {
            let started = h.started();
            if started.is_empty() {
                break;
            }
            for (service, run) in started {
                h.run_started(&service, run);
                runs.insert(service, run);
            }
        }
        assert_eq!(runs.len(), 5);

        h.engine.shutdown();
        let stops = |h: &mut Harness| h.stops().0;
        assert_eq!(stops(&mut h), ["time-controller", "workload-web"]);
        let finish = |h: &mut Harness, service: &str| {
            h.run_finished(service, runs[service], Exit::Signal(15));
            assert_eq!(h.state(service), State::Stopped);
        };
        finish(&mut h, "workload-web");
        assert_eq!(stops(&mut h), ["containerd"]);
        finish(&mut h, "time-controller");
        assert!(stops(&mut h).is_empty(), "containerd still needs setup");
        finish(&mut h, "containerd");
        assert_eq!(stops(&mut h), ["setup"]);
        finish(&mut h, "setup");
        assert_eq!(stops(&mut h), ["network-controller"]);
        assert!(!h.engine.stopped());
        finish(&mut h, "network-controller");
        assert!(h.engine.stopped());
        assert_eq!(h.state("pending"), State::Stopped);
    }
}

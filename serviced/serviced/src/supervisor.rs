//! The supervisor's loop: it feeds the [`Engine`] with the service files, what serviced's API
//! asks and what becomes of the runs, carries out its actions, listens on the services' sockets
//! and updates what the API shows, until a power request; then it shuts down:
//! 0. the holders of delay locks (`WatchShutdown`) are told, and their release awaited, at most
//!    their longest delay: the services still run (kubelet stops its pods);
//! 1. the running services stop, dependents first, with their `exec-post`;
//! 2. the processes they left (containers) are terminated, then killed;
//! 3. the services that ran run their `exec-stop`, one at a time, the last started first: nothing
//!    holds what they undo any more (storage-controller unmounts `/var`).
//!
//! The kernel reboots or powers off next ([`shutdown::finish`](crate::shutdown::finish)).
//!
//! The service files are read at boot, when the API asks (a service wrote or removed some), and
//! when a service gets ready or ends: a layer may have appeared (storage-controller mounted
//! `/var`, with the persistent services), read before the services that come after start, and
//! before boot can be complete. Each read makes the sockets of the enabled services whose
//! condition holds, before any of them starts, and removes those of the others: a caller can
//! connect as soon as the read is over, and finds no socket, rather than one never answered, when
//! its service cannot run.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use libserviced::definition;
use libserviced::definition::{Layer, LogDir, Service, ServiceName};
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::{error, info, warn};

use crate::activation_watch;
use crate::caller::Resolver;
use crate::command::Command;
use crate::engine::{Action, Engine, Event, Outcome, RunId};
use crate::log_store::LogStore;
use crate::notify_socket::{self, NotifySocket};
use crate::overview::{Overview, ServiceView};
use crate::power::PowerRequest;
use crate::process::Reaper;
use crate::run::{self, Launch, RunKind};
use crate::service_sockets::{self, Listener, ServiceSockets};
use crate::shutdown;
use crate::shutdown_locks::ShutdownLocks;

/// serviced's state: the engine, the runs carrying out its actions, and what feeds it.
pub struct Supervisor {
    engine: Engine,
    reaper: Reaper,
    runs: HashMap<ServiceName, run::Handle>,
    events: mpsc::UnboundedSender<Event>,
    received: mpsc::UnboundedReceiver<Event>,
    commands: mpsc::UnboundedReceiver<Command>,
    /// The log file of each service's last run, where its `exec-stop` alone writes too.
    log_files: HashMap<ServiceName, PathBuf>,
    logs: Arc<LogStore>,
    overview: Arc<Overview>,
    notify_sockets: HashMap<ServiceName, NotifySocket>,
    /// The sockets of the enabled services whose condition holds.
    sockets: HashMap<ServiceName, ServiceSockets>,
    /// The sockets of the socket-activated services waiting for a connection.
    watches: HashMap<ServiceName, JoinSet<()>>,
    /// Finds the service of the senders of notifications.
    resolve: Resolver,
    /// The layers of each service, as last loaded.
    layers: BTreeMap<ServiceName, Vec<Layer>>,
    /// The errors of the last load, logged when they change.
    load_errors: Vec<String>,
    /// The delay locks a shutdown waits for.
    shutdown_locks: Arc<ShutdownLocks>,
}

impl Supervisor {
    /// A supervisor spawning the services' processes through `reaper`, carrying out `commands`,
    /// keeping their logs in `logs`, showing them in `overview`, and waiting for
    /// `shutdown_locks` before a shutdown.
    #[must_use]
    pub fn new(
        reaper: Reaper,
        commands: mpsc::UnboundedReceiver<Command>,
        logs: Arc<LogStore>,
        overview: Arc<Overview>,
        resolve: Resolver,
        shutdown_locks: Arc<ShutdownLocks>,
    ) -> Self {
        let (events, received) = mpsc::unbounded_channel();
        Self {
            engine: Engine::new(Path::exists),
            reaper,
            runs: HashMap::new(),
            events,
            received,
            commands,
            log_files: HashMap::new(),
            logs,
            overview,
            notify_sockets: HashMap::new(),
            sockets: HashMap::new(),
            watches: HashMap::new(),
            resolve,
            layers: BTreeMap::new(),
            load_errors: Vec::new(),
            shutdown_locks,
        }
    }

    /// Runs the services until a power request, then stops them; returns the request.
    pub async fn run(mut self, mut power: mpsc::Receiver<PowerRequest>) -> PowerRequest {
        self.reload().await;
        let request = loop {
            tokio::select! {
                Some(event) = self.received.recv() => {
                    let may_add_layer = match &event {
                        Event::Finished { .. } => true,
                        Event::Notified { notification, .. } => notification.ready,
                        _ => false,
                    };
                    if may_add_layer {
                        self.reload().await;
                    }
                    self.event(event).await;
                }
                Some(command) = self.commands.recv() => self.command(command).await,
                Some(request) = power.recv() => break request,
            }
        };

        info!(?request, "shutting down");
        self.delay_shutdown(&mut power).await;
        self.engine.shutdown();
        self.apply().await;
        self.wait_stopped(&mut power).await;
        info!("every service stopped");
        shutdown::terminate_all(&self.reaper).await;
        self.engine.run_exec_stops();
        self.apply().await;
        self.wait_stopped(&mut power).await;
        request
    }

    /// Announces the shutdown to the holders of delay locks, and goes on supervising until they
    /// release them or the longest delay passed.
    async fn delay_shutdown(&mut self, power: &mut mpsc::Receiver<PowerRequest>) {
        let locks = Arc::clone(&self.shutdown_locks);
        let Some(delay) = locks.announce() else {
            return;
        };
        info!(
            delay_s = delay.as_secs(),
            "waiting for the shutdown's delay locks"
        );
        let deadline = tokio::time::Instant::now() + delay;
        let released = locks.released();
        tokio::pin!(released);
        loop {
            tokio::select! {
                () = &mut released => {
                    info!("delay locks released");
                    return;
                }
                () = tokio::time::sleep_until(deadline) => {
                    warn!(delay_s = delay.as_secs(), "delay locks still held, shutting down");
                    return;
                }
                Some(event) = self.received.recv() => self.event(event).await,
                Some(command) = self.commands.recv() => self.command(command).await,
                Some(other) = power.recv() => info!(request = ?other, "already shutting down"),
            }
        }
    }

    /// Handles the runs' events until the engine has nothing running; the API's requests are
    /// refused.
    async fn wait_stopped(&mut self, power: &mut mpsc::Receiver<PowerRequest>) {
        while !self.engine.stopped() {
            tokio::select! {
                Some(event) = self.received.recv() => self.event(event).await,
                Some(command) = self.commands.recv() => self.command(command).await,
                Some(other) = power.recv() => info!(request = ?other, "already shutting down"),
            }
        }
    }

    /// Carries out `command`, and answers it.
    async fn command(&mut self, command: Command) {
        match command {
            Command::Start(service, reply) => {
                let _ = reply.send(self.engine.start(&service));
            }
            Command::Stop(service, reply) => {
                let _ = reply.send(self.engine.stop_service(&service));
            }
            Command::Restart(service, reply) => {
                let _ = reply.send(self.engine.restart(&service));
            }
            Command::Reload(reply) => {
                self.reload().await;
                let _ = reply.send(self.load_errors.clone());
                return;
            }
        }
        self.apply().await;
    }

    /// Reads the layers again, makes and removes sockets, and applies the differences.
    async fn reload(&mut self) {
        let (loaded, errors) = definition::load(&Layer::ALL.map(|layer| (layer, layer.dir())));
        let errors: Vec<String> = errors.iter().map(ToString::to_string).collect();
        if errors != self.load_errors {
            for e in &errors {
                error!("invalid service, left out: {e}");
            }
            self.load_errors = errors;
        }
        self.layers.clear();
        let mut services = BTreeMap::new();
        for (name, loaded) in loaded {
            self.layers.insert(name.clone(), loaded.layers);
            services.insert(name, loaded.service);
        }
        self.listen(&services);
        self.engine.reload(services);
        self.apply().await;
    }

    /// Makes the sockets of `services` that are enabled and whose condition holds; removes the
    /// others, and those whose definition changed.
    fn listen(&mut self, services: &BTreeMap<ServiceName, Service>) {
        let stale: Vec<ServiceName> = self
            .sockets
            .iter()
            .filter(|(name, sockets)| {
                services
                    .get(*name)
                    .is_none_or(|service| !listens(service) || !sockets.match_definition(service))
            })
            .map(|(name, _)| name.clone())
            .collect();
        for name in stale {
            self.watches.remove(&name);
            self.sockets.remove(&name);
            info!(service = %name, "sockets removed");
        }
        for (name, service) in services {
            if listens(service)
                && !self.sockets.contains_key(name)
                && let Err(e) = self.bind(name, service)
            {
                error!(service = %name, "cannot listen on the service's sockets: {e:#}");
            }
        }
    }

    /// Makes the sockets of `service`, `name`.
    fn bind(&mut self, name: &ServiceName, service: &Service) -> anyhow::Result<()> {
        self.watches.remove(name);
        self.sockets.remove(name);
        let sockets = ServiceSockets::bind(service)?;
        for listener in sockets.listeners() {
            info!(
                service = %name,
                socket = %listener.socket.name,
                path = %listener.socket.path,
                "listening"
            );
        }
        self.sockets.insert(name.clone(), sockets);
        Ok(())
    }

    /// Hands `event` to the engine, and carries out what follows.
    async fn event(&mut self, event: Event) {
        if let Event::Finished { service, run, .. } = &event
            && self
                .runs
                .get(service)
                .is_some_and(|handle| handle.run == *run)
        {
            self.runs.remove(service);
        }
        self.engine.handle(event, Instant::now());
        self.apply().await;
    }

    /// Carries out the engine's actions, watches the sockets of the services waiting for a
    /// connection, and shows the services as they are now.
    async fn apply(&mut self) {
        for action in self.engine.take_actions() {
            match action {
                Action::Start {
                    service,
                    run,
                    definition,
                } => self.start(service, run, definition, RunKind::Full).await,
                Action::ExecStop {
                    service,
                    run,
                    definition,
                } => {
                    self.start(service, run, definition, RunKind::ExecStop)
                        .await
                }
                Action::Stop {
                    service,
                    run,
                    exec_stop,
                } => {
                    if let Some(handle) = self.runs.get(&service)
                        && handle.run == run
                    {
                        handle.stop(exec_stop);
                    }
                }
                Action::Schedule {
                    service,
                    token,
                    delay,
                } => {
                    let events = self.events.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(delay).await;
                        let _ = events.send(Event::BackoffElapsed { service, token });
                    });
                }
                Action::ShowCrash { service, lines } => {
                    warn!(service = %service, "the service's last output:");
                    for line in lines {
                        warn!("[{service}] {line}");
                    }
                }
            }
        }
        // What the engine forgot (removed services, once stopped) goes.
        let engine = &self.engine;
        self.notify_sockets
            .retain(|service, _| engine.contains(service));
        self.log_files.retain(|service, _| engine.contains(service));
        self.watch();
        self.show().await;
    }

    /// Watches the sockets of the services waiting for a connection, and only those.
    fn watch(&mut self) {
        let awaiting = self.engine.awaiting_connection();
        self.watches.retain(|service, _| awaiting.contains(service));
        for service in awaiting {
            if self.watches.contains_key(&service) {
                continue;
            }
            let Some(sockets) = self.sockets.get(&service) else {
                continue;
            };
            match activation_watch::start(&service, sockets.listeners(), &self.events) {
                Ok(watch) => {
                    self.watches.insert(service, watch);
                }
                Err(e) => warn!(service = %service, "cannot watch the service's sockets: {e}"),
            }
        }
    }

    /// Starts run `run` of `service`, defined as `definition`: all of it, or its `exec-stop`
    /// alone (in the log file of its last run: storage-controller's is in /run, not on the /var
    /// it unmounts).
    async fn start(
        &mut self,
        service: ServiceName,
        run: RunId,
        definition: Arc<Service>,
        kind: RunKind,
    ) {
        let log = match kind {
            RunKind::Full => {
                let log = log_path(&service);
                self.log_files.insert(service.clone(), log.clone());
                log
            }
            RunKind::ExecStop => self
                .log_files
                .get(&service)
                .cloned()
                .unwrap_or_else(|| log_path(&service)),
        };
        let not_started = |reason: String| Event::Finished {
            service: service.clone(),
            run,
            outcome: Outcome::NotStarted {
                reason,
                tail: Vec::new(),
            },
        };
        let sockets = match kind {
            RunKind::Full => match self.sockets_of(&service, &definition) {
                Ok(sockets) => sockets,
                Err(e) => {
                    let _ = self.events.send(not_started(format!("sockets: {e:#}")));
                    return;
                }
            },
            RunKind::ExecStop => Vec::new(),
        };
        let user = definition
            .sandbox
            .as_ref()
            .map_or(0, |sandbox| sandbox.user);
        let notify_socket = match self.notify_socket(&service, user) {
            Ok(socket) => socket,
            Err(e) => {
                let _ = self
                    .events
                    .send(not_started(format!("notify socket: {e:#}")));
                return;
            }
        };
        let allowed_sockets = service_sockets::allowed_sockets(
            &service,
            self.engine
                .services()
                .map(|(_, definition, _)| definition.as_ref()),
        );
        let launch = Launch {
            kind,
            name: service.clone(),
            service: definition,
            run,
            log,
            log_buffer: self.logs.service(&service).await,
            notify_socket,
            sockets,
            allowed_sockets,
            own_cgroup: true,
        };
        let handle = run::start(launch, self.reaper.clone(), self.events.clone());
        self.runs.insert(service, handle);
    }

    /// The sockets of `service`, defined as `definition`, made now if they are missing or were
    /// made for another definition (its condition just became true, or binding failed before).
    fn sockets_of(
        &mut self,
        service: &ServiceName,
        definition: &Service,
    ) -> anyhow::Result<Vec<Listener>> {
        if definition.sockets.is_empty() {
            return Ok(Vec::new());
        }
        let current = self
            .sockets
            .get(service)
            .is_some_and(|sockets| sockets.match_definition(definition));
        if !current {
            self.bind(service, definition)?;
        }
        Ok(self.sockets[service].listeners().to_vec())
    }

    /// The path of the notify socket of `service`, made if needed, owned by `user`.
    fn notify_socket(&mut self, service: &ServiceName, user: u32) -> anyhow::Result<PathBuf> {
        if let Some(socket) = self.notify_sockets.get(service) {
            socket.chown(user)?;
            return Ok(socket.path().to_owned());
        }
        let socket = NotifySocket::bind(
            Path::new(notify_socket::DIR),
            service,
            user,
            self.resolve.clone(),
            self.events.clone(),
        )?;
        let path = socket.path().to_owned();
        self.notify_sockets.insert(service.clone(), socket);
        Ok(path)
    }

    /// Updates what the API shows: the services.
    async fn show(&self) {
        let services = self
            .engine
            .services()
            .map(|(name, service, status)| {
                let view = ServiceView {
                    definition: service.clone(),
                    layers: self.layers.get(name).cloned().unwrap_or_default(),
                    status: status.clone(),
                };
                (name.clone(), view)
            })
            .collect();
        self.overview.set_services(services).await;
    }
}

/// Whether serviced listens on the sockets of `service`: it has some, it is enabled, and its
/// condition holds (its callers then fail at once rather than wait for it).
#[must_use]
fn listens(service: &Service) -> bool {
    !service.sockets.is_empty()
        && service.enabled
        && service
            .condition
            .path_exists
            .as_deref()
            .is_none_or(Path::exists)
}

/// Where a run starting now logs: on /var once storage-controller mounted it, before in /run.
#[must_use]
fn log_path(service: &ServiceName) -> PathBuf {
    let dir = if Path::new(definition::VAR_LOG_DIR).is_dir() {
        LogDir::Var
    } else {
        LogDir::Run
    };
    definition::log_path(service, dir)
}

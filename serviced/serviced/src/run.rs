//! One run of a service: its `exec-pre` commands, `exec`, then its `exec-post` commands, and its
//! `exec-stop` commands if it was stopped; or, at shutdown, its `exec-stop` commands alone, left
//! for once every other process is gone. Each is a child of serviced confined as the service says,
//! its output in the service's log. What happens is reported to the engine as [`Event`]s.
//!
//! Children get only the service's environment and `NOTIFY_SOCKET`, `/dev/null` as standard
//! input, `/` as working directory, and a pipe serviced reads as standard output and error.
//! `exec` also gets the service's sockets ([`listen_exec`](crate::listen_exec)).

use std::ffi::CString;
use std::future::Future;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use libserviced::definition::{AbsolutePath, Command, Service, ServiceName};
use tokio::net::unix::pipe;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::engine::{Event, Outcome, RunId};
use crate::exit::Exit;
use crate::listen_exec::{self, ListenExec, PassedFds};
use crate::log_buffer::LogBuffer;
use crate::mounts;
use crate::process::{self, Child, Reaper};
use crate::sandbox::{self, Prepared, Spec};
use crate::service_log::{self, ServiceLog};
use crate::service_sockets::Listener;

/// How long the output of an exited process may still be read: a process it left behind may
/// hold the pipe open.
const OUTPUT_DRAIN: Duration = Duration::from_secs(1);
/// How long a stopped process has after SIGTERM before SIGKILL, and each `exec-post` or
/// `exec-stop` command has once the run is stopped (1 s in tests, which wait for it).
const STOP_TIMEOUT: Duration = Duration::from_secs(if cfg!(test) { 1 } else { 10 });

/// A run in progress. Once it is dropped, the run can no longer be stopped.
#[must_use]
pub struct Handle {
    /// The run's ID, as given to [`start`].
    pub run: RunId,
    /// Set once the run is to stop: whether it runs `exec-stop` then.
    stop: watch::Sender<Option<bool>>,
}

impl Handle {
    /// Stops the run: SIGTERM, SIGKILL after the stop timeout, then `exec-post`, and
    /// `exec-stop` if asked (it may be left for later). The engine stops a run once.
    pub fn stop(&self, exec_stop: bool) {
        self.stop.send_replace(Some(exec_stop));
    }
}

/// What a run runs.
pub enum RunKind {
    /// `exec-pre`, `exec`, `exec-post`.
    Full,
    /// The `exec-stop` commands alone (left for later at shutdown).
    ExecStop,
}

/// A run to start.
pub struct Launch {
    pub kind: RunKind,
    pub name: ServiceName,
    pub service: Arc<Service>,
    pub run: RunId,
    /// The log file its output is appended to.
    pub log: PathBuf,
    /// Its log in memory.
    pub log_buffer: Arc<LogBuffer>,
    /// The service's notify socket, given to its processes.
    pub notify_socket: PathBuf,
    /// The service's sockets, passed to `exec`.
    pub sockets: Vec<Listener>,
    /// The sockets of others whose `allow` names the service, bound in a sandbox.
    pub allowed_sockets: Vec<AbsolutePath>,
    /// Whether an unconfined service's processes go to the service's cgroup: always, but for the
    /// tests, which are not PID 1.
    pub own_cgroup: bool,
}

/// Starts `launch` through `reaper`; what happens is sent to `events`.
pub fn start(launch: Launch, reaper: Reaper, events: mpsc::UnboundedSender<Event>) -> Handle {
    let (stop, stopped) = watch::channel(None);
    let run = launch.run;
    let runner = Runner {
        reaper,
        events,
        stop: stopped,
        launch,
    };
    tokio::spawn(runner.execute());
    Handle { run, stop }
}

/// A run, carried out by its own task.
struct Runner {
    reaper: Reaper,
    events: mpsc::UnboundedSender<Event>,
    stop: watch::Receiver<Option<bool>>,
    launch: Launch,
}

/// Where a service's processes go.
enum Confinement {
    /// The host, as root, in the service's cgroup (but in tests).
    Unconfined(Option<CString>),
    Sandbox(Arc<Prepared>),
}

impl Runner {
    /// Carries out the run, then reports its end.
    async fn execute(mut self) {
        let launch = &self.launch;
        let log = ServiceLog::open(
            launch.name.clone(),
            launch.log.clone(),
            launch.log_buffer.clone(),
            launch.service.console,
        )
        .await;
        let outcome = match launch.kind {
            RunKind::Full => self.full_run(&log).await,
            RunKind::ExecStop => {
                match self.confine() {
                    Ok(confinement) => self.exec_stop(&confinement, &log).await,
                    Err(e) => {
                        warn!(
                            service = %self.launch.name,
                            error = format!("{e:#}"),
                            "exec-stop failed"
                        )
                    }
                }
                Outcome::NotStarted {
                    reason: "stopped".to_owned(),
                    tail: Vec::new(),
                }
            }
        };
        self.send(|service, run| Event::Finished {
            service,
            run,
            outcome,
        });
    }

    /// `exec-pre`, `exec`, `exec-post`, then `exec-stop` if the run was stopped and asked to.
    async fn full_run(&mut self, log: &Arc<ServiceLog>) -> Outcome {
        let confinement = match self.prepare() {
            Ok(confinement) => confinement,
            Err(e) => {
                return Outcome::NotStarted {
                    reason: format!("{e:#}"),
                    tail: Vec::new(),
                };
            }
        };
        let outcome = self.attempt(&confinement, log).await;
        for command in &self.launch.service.exec_post {
            let mut stop = self.stop.clone();
            // Run to its end, unless the run is stopped and it outlasts the stop timeout.
            let deadline = async move {
                stop_requested(&mut stop).await;
                tokio::time::sleep(STOP_TIMEOUT).await;
            };
            self.cleanup("exec-post", command, &confinement, log, deadline)
                .await;
        }
        if *self.stop.borrow() == Some(true) {
            self.exec_stop(&confinement, log).await;
        }
        outcome
    }

    /// Sends the event `event` makes of the service's name and the run's ID.
    fn send(&self, event: impl FnOnce(ServiceName, RunId) -> Event) {
        let _ = self
            .events
            .send(event(self.launch.name.clone(), self.launch.run));
    }

    /// Creates the runtime directories, and builds the confinement.
    fn prepare(&self) -> anyhow::Result<Confinement> {
        let service = &self.launch.service;
        let owner = service.sandbox.as_ref().map_or(0, |sandbox| sandbox.user);
        for dir in &service.runtime_directories {
            mounts::create_dir(dir, owner, 0o755)?;
        }
        self.confine()
    }

    /// Builds the confinement of the service's processes: its sandbox, or its cgroup.
    fn confine(&self) -> anyhow::Result<Confinement> {
        use anyhow::Context as _;

        let launch = &self.launch;
        match &launch.service.sandbox {
            Some(sandbox) => {
                let spec = Spec::try_new(
                    &launch.name,
                    &launch.service,
                    sandbox,
                    &launch.notify_socket,
                    &launch.allowed_sockets,
                )?;
                let prepared = Prepared::try_new(&spec).context("preparing the sandbox")?;
                Ok(Confinement::Sandbox(Arc::new(prepared)))
            }
            None if launch.own_cgroup => {
                let procs = sandbox::unconfined_cgroup(&launch.name)
                    .context("creating the service's cgroup")?;
                Ok(Confinement::Unconfined(Some(procs)))
            }
            None => Ok(Confinement::Unconfined(None)),
        }
    }

    /// `exec-pre`, then `exec` until it exits or is stopped.
    async fn attempt(&mut self, confinement: &Confinement, log: &Arc<ServiceLog>) -> Outcome {
        let not_started = async |reason: String| Outcome::NotStarted {
            reason,
            tail: log.tail().await,
        };
        let service = &self.launch.service;
        for command in &service.exec_pre {
            if self.stop.borrow().is_some() {
                return not_started("stopped before starting".to_owned()).await;
            }
            let (child, output) = match self.spawn(command, confinement, log, &[]).await {
                Ok(spawned) => spawned,
                Err(e) if command.may_fail() => {
                    warn!(
                        service = %self.launch.name,
                        error = format!("{e:#}"),
                        "exec-pre failed, ignored"
                    );
                    continue;
                }
                Err(e) => return not_started(format!("exec-pre: {e:#}")).await,
            };
            let pid = child.pid;
            let mut wait = std::pin::pin!(child.wait());
            let (exit, stopped) = tokio::select! {
                exit = &mut wait => (exit, false),
                () = stop_requested(&mut self.stop) => {
                    (terminate(wait.as_mut(), pid).await, true)
                }
            };
            drain(output).await;
            if stopped {
                return not_started("stopped before starting".to_owned()).await;
            }
            if !exit.success() {
                if command.may_fail() {
                    debug!(
                        service = %self.launch.name,
                        program = %command.program(),
                        %exit,
                        "exec-pre failed, ignored"
                    );
                } else {
                    return not_started(format!("exec-pre {}: {exit}", command.program())).await;
                }
            }
        }
        if self.stop.borrow().is_some() {
            return not_started("stopped before starting".to_owned()).await;
        }

        let sockets = &self.launch.sockets;
        let (child, output) = match self.spawn(&service.exec, confinement, log, sockets).await {
            Ok(spawned) => spawned,
            Err(e) => return not_started(format!("{e:#}")).await,
        };
        let pid = child.pid;
        self.send(|service, run| Event::Started { service, run, pid });
        let mut wait = std::pin::pin!(child.wait());
        let exit = tokio::select! {
            exit = &mut wait => exit,
            () = stop_requested(&mut self.stop) => terminate(wait.as_mut(), pid).await,
        };
        self.send(|service, run| Event::Exited { service, run, exit });
        drain(output).await;
        Outcome::Exited {
            exit,
            tail: log.tail().await,
        }
    }

    /// The `exec-stop` commands, each given the stop timeout.
    async fn exec_stop(&self, confinement: &Confinement, log: &Arc<ServiceLog>) {
        for command in &self.launch.service.exec_stop {
            let deadline = tokio::time::sleep(STOP_TIMEOUT);
            self.cleanup("exec-stop", command, confinement, log, deadline)
                .await;
        }
    }

    /// An `exec-post` or `exec-stop` command (`what`): it runs to its end, unless `deadline`
    /// comes first (then SIGKILL).
    async fn cleanup(
        &self,
        what: &str,
        command: &Command,
        confinement: &Confinement,
        log: &Arc<ServiceLog>,
        deadline: impl Future<Output = ()>,
    ) {
        let (child, output) = match self.spawn(command, confinement, log, &[]).await {
            Ok(spawned) => spawned,
            Err(e) => {
                warn!(
                    service = %self.launch.name,
                    command = what,
                    error = format!("{e:#}"),
                    "cannot run"
                );
                return;
            }
        };
        let pid = child.pid;
        let mut wait = std::pin::pin!(child.wait());
        let exit = tokio::select! {
            exit = &mut wait => exit,
            () = deadline => {
                warn!(
                    service = %self.launch.name,
                    program = %command.program(),
                    "{what} outlasted the stop timeout, killing it"
                );
                process::signal_process(pid, libc::SIGKILL);
                wait.await
            }
        };
        drain(output).await;
        if !exit.success() && !command.may_fail() {
            warn!(
                service = %self.launch.name,
                program = %command.program(),
                %exit,
                "{what} failed"
            );
        }
    }

    /// Spawns `command` through the reaper with `sockets`, its output read into `log`.
    async fn spawn(
        &self,
        command: &Command,
        confinement: &Confinement,
        log: &Arc<ServiceLog>,
        sockets: &[Listener],
    ) -> anyhow::Result<(Child, JoinHandle<()>)> {
        use anyhow::Context as _;
        use std::os::unix::process::CommandExt as _;

        let launch = &self.launch;
        let program = command.program().as_str();
        let notify_socket = launch
            .notify_socket
            .to_str()
            .context("the notify socket is not UTF-8")?;
        let listen = match sockets {
            [] => Vec::new(),
            sockets => listen_exec::environment(sockets),
        };
        let environment: Vec<(&str, &str)> = launch
            .service
            .env
            .iter()
            .chain(listen.iter().map(|(key, value)| (key, value)))
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .chain([(libserviced::notify::SOCKET_VARIABLE, notify_socket)])
            .collect();
        let (reader, writer) = std::io::pipe().context("creating the output pipe")?;
        let mut process = std::process::Command::new(program);
        process
            .args(command.args())
            .env_clear()
            .envs(environment.iter().copied())
            .stdin(Stdio::null())
            .stdout(writer.try_clone()?)
            .stderr(writer)
            .current_dir("/");
        if !sockets.is_empty() {
            let mut fds = PassedFds::new(sockets);
            // SAFETY: the closure runs in the forked child, where only async-signal-safe code
            // may run: `place` only makes system calls on prepared fds. It runs first, before
            // the sandbox's seccomp filter forbids `dup2`.
            unsafe {
                process.pre_exec(move || fds.place());
            }
        }
        match confinement {
            Confinement::Sandbox(prepared) => {
                let prepared = prepared.clone();
                // `pre_exec` is the only hook between `fork` and `exec` std offers.
                // SAFETY: the closure runs in the forked child, where only async-signal-safe code
                // may run: `enter` only makes system calls on the prepared arguments; it does not
                // allocate or take locks.
                unsafe {
                    process.pre_exec(move || sandbox::enter(&prepared));
                }
            }
            Confinement::Unconfined(Some(procs)) => {
                let procs = procs.clone();
                // SAFETY: the closure runs in the forked child, where only async-signal-safe code
                // may run: `join_cgroup` only makes system calls on its prepared path.
                unsafe {
                    process.pre_exec(move || sandbox::join_cgroup(&procs));
                }
            }
            Confinement::Unconfined(None) => {}
        }
        if !sockets.is_empty() {
            let variables = environment.iter().copied();
            let mut exec = ListenExec::try_new(program, command.args(), variables)?;
            // SAFETY: the closure runs in the forked child, where only async-signal-safe code
            // may run: `exec` only writes into its prepared buffers and makes system calls. It
            // runs last: it replaces std's own `execvp`, to set `LISTEN_PID`.
            unsafe {
                process.pre_exec(move || Err(exec.exec()));
            }
        }
        let child = self
            .reaper
            .spawn(&mut process)
            .await
            .with_context(|| format!("starting {program}"))?;
        // The command holds the write ends: drop them so the reader ends with the process.
        drop(process);
        let reader = pipe::Receiver::from_owned_fd(OwnedFd::from(reader))?;
        // What may fail is cleanup, whose complaints (nothing to clean) stay in the log.
        let quiet = command.may_fail();
        let output = tokio::spawn(service_log::pump(reader, log.clone(), quiet));
        if let Confinement::Sandbox(_) = confinement {
            sandbox::log_confinement(&launch.name, program, child.pid);
        } else {
            debug!(service = %launch.name, program, pid = child.pid, "process started");
        }
        Ok((child, output))
    }
}

/// Resolves once the run is to stop (never if nobody can ask any more).
async fn stop_requested(stop: &mut watch::Receiver<Option<bool>>) {
    if stop.wait_for(Option::is_some).await.is_err() {
        std::future::pending::<()>().await;
    }
}

/// SIGTERM, then SIGKILL after the stop timeout.
async fn terminate(mut wait: Pin<&mut impl Future<Output = Exit>>, pid: u32) -> Exit {
    process::signal_process(pid, libc::SIGTERM);
    match tokio::time::timeout(STOP_TIMEOUT, &mut wait).await {
        Ok(exit) => exit,
        Err(_) => {
            warn!(pid, "process did not stop in time, killing it");
            process::signal_process(pid, libc::SIGKILL);
            wait.await
        }
    }
}

/// Lets the output of an exited process be read to its end, for a while.
async fn drain(output: JoinHandle<()>) {
    let _ = tokio::time::timeout(OUTPUT_DRAIN, output).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Test {
        dir: tempfile::TempDir,
        events: mpsc::UnboundedReceiver<Event>,
        sender: mpsc::UnboundedSender<Event>,
        sockets: Vec<Listener>,
    }

    impl Test {
        fn new() -> Self {
            let (sender, events) = mpsc::unbounded_channel();
            Self {
                dir: tempfile::tempdir().unwrap(),
                events,
                sender,
                sockets: Vec::new(),
            }
        }

        /// Starts service `text`, where `{dir}` is a temporary directory and `{sleep}` the
        /// program.
        fn start(&self, text: &str) -> Handle {
            self.launch(text, RunKind::Full)
        }

        fn launch(&self, text: &str, kind: RunKind) -> Handle {
            let sleep = std::env::split_paths(&std::env::var_os("PATH").unwrap())
                .map(|dir| dir.join("sleep"))
                .find(|path| path.exists())
                .expect("sleep in PATH");
            let text = text
                .replace("{dir}", self.dir.path().to_str().unwrap())
                .replace("{sleep}", sleep.to_str().unwrap());
            let service: Arc<Service> = Arc::new(toml::from_str(&text).unwrap());
            let launch = Launch {
                kind,
                name: "test".parse().unwrap(),
                service,
                run: 7,
                log: self.dir.path().join("test.log"),
                log_buffer: Arc::new(LogBuffer::new(100, 1 << 20)),
                notify_socket: self.dir.path().join("notify"),
                sockets: self.sockets.clone(),
                allowed_sockets: Vec::new(),
                own_cgroup: false,
            };
            start(launch, process::test_reaper(), self.sender.clone())
        }

        async fn next(&mut self) -> Event {
            tokio::time::timeout(Duration::from_secs(10), self.events.recv())
                .await
                .expect("an event")
                .unwrap()
        }

        fn log(&self) -> String {
            std::fs::read_to_string(self.dir.path().join("test.log")).unwrap()
        }
    }

    #[tokio::test]
    async fn runs_pre_exec_and_post() {
        let mut test = Test::new();
        let _handle = test.start(
            r#"
exec = ["/bin/sh", "-c", "echo main $GREETING; echo oops >&2; exit 3"]
exec-pre = [["/bin/sh", "-c", "echo pre"], ["-/bin/sh", "-c", "exit 1"]]
exec-post = [["/bin/sh", "-c", "echo post"]]
exec-stop = [["/bin/sh", "-c", "echo stop"]]
env.GREETING = "hello"
"#,
        );
        assert!(matches!(test.next().await, Event::Started { run: 7, .. }));
        assert!(matches!(
            test.next().await,
            Event::Exited {
                exit: Exit::Code(3),
                ..
            }
        ));
        let Event::Finished { outcome, .. } = test.next().await else {
            panic!("finished expected");
        };
        assert_eq!(
            outcome,
            Outcome::Exited {
                exit: Exit::Code(3),
                tail: vec!["pre".into(), "main hello".into(), "oops".into()],
            }
        );
        assert_eq!(
            test.log(),
            "pre\nmain hello\noops\npost\n",
            "exec-stop only runs when stopped"
        );
    }

    #[tokio::test]
    async fn stopped_runs_run_exec_stop() {
        let mut test = Test::new();
        let handle = test.start(
            r#"
exec = ["{sleep}", "30"]
exec-post = [["/bin/sh", "-c", "echo post"]]
exec-stop = [["/bin/sh", "-c", "echo stop"], ["-/bin/sh", "-c", "exit 1"]]
"#,
        );
        assert!(matches!(test.next().await, Event::Started { .. }));
        handle.stop(/* exec_stop */ true);
        assert!(matches!(test.next().await, Event::Exited { .. }));
        assert!(matches!(test.next().await, Event::Finished { .. }));
        assert_eq!(test.log(), "post\nstop\n");

        // Unless it is left for later.
        let mut test = Test::new();
        let handle = test.start(
            r#"
exec = ["{sleep}", "30"]
exec-stop = [["/bin/sh", "-c", "echo stop"]]
"#,
        );
        assert!(matches!(test.next().await, Event::Started { .. }));
        handle.stop(/* exec_stop */ false);
        assert!(matches!(test.next().await, Event::Exited { .. }));
        assert!(matches!(test.next().await, Event::Finished { .. }));
        assert_eq!(test.log(), "");
    }

    #[tokio::test]
    async fn exec_stop_alone_is_given_the_stop_timeout() {
        let mut test = Test::new();
        let _handle = test.launch(
            r#"
exec = ["/bin/sh", "-c", "echo never"]
exec-post = [["/bin/sh", "-c", "echo never"]]
exec-stop = [
    ["/bin/sh", "-c", "echo undo"],
    ["/bin/sh", "-c", "trap '' TERM; exec {sleep} 30"],
    ["/bin/sh", "-c", "echo next"],
]
"#,
            RunKind::ExecStop,
        );
        let started = std::time::Instant::now();
        assert!(
            matches!(test.next().await, Event::Finished { .. }),
            "and nothing else"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "the command ignoring SIGTERM is killed after the 1s stop timeout, took {:?}",
            started.elapsed()
        );
        assert_eq!(test.log(), "undo\nnext\n");
    }

    #[tokio::test]
    async fn exec_pre_failure_skips_exec() {
        let mut test = Test::new();
        let _handle = test.start(
            r#"
exec = ["/bin/sh", "-c", "echo never"]
exec-pre = [["/bin/sh", "-c", "echo cannot pull; exit 1"]]
exec-post = [["/bin/sh", "-c", "echo cleaned"]]
"#,
        );
        let Event::Finished { outcome, .. } = test.next().await else {
            panic!("finished expected");
        };
        assert_eq!(
            outcome,
            Outcome::NotStarted {
                reason: "exec-pre /bin/sh: exit code 1".into(),
                tail: vec!["cannot pull".into()],
            }
        );
        assert_eq!(test.log(), "cannot pull\ncleaned\n");
    }

    #[tokio::test]
    async fn daemons_get_their_notify_socket_and_stop() {
        let mut test = Test::new();
        let handle = test.start(
            r#"
exec = ["/bin/sh", "-c", "echo $NOTIFY_SOCKET; exec {sleep} 30"]
"#,
        );
        assert!(matches!(test.next().await, Event::Started { .. }));
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            test.log(),
            format!("{}\n", test.dir.path().join("notify").display())
        );
        handle.stop(/* exec_stop */ true);
        assert!(matches!(
            test.next().await,
            Event::Exited {
                exit: Exit::Signal(15),
                ..
            }
        ));
        assert!(matches!(test.next().await, Event::Finished { .. }));
    }

    #[tokio::test]
    async fn exec_gets_the_service_s_sockets() {
        let mut test = Test::new();
        let path = test.dir.path().join("api.sock");
        let fd = std::os::unix::net::UnixListener::bind(&path).unwrap();
        test.sockets.push(Listener {
            socket: toml::from_str(&format!(
                "name = \"api\"\npath = {path:?}\nallow = [\"a\", \"b\"]\n"
            ))
            .unwrap(),
            fd: Arc::new(OwnedFd::from(fd)),
        });
        let _handle = test.start(
            r#"
exec = [
    "/bin/sh",
    "-c",
    """echo $LISTEN_FDS $LISTEN_FDNAMES $SERVICED_ALLOW_API $GREETING; \
       test "$LISTEN_PID" = $$ && test -S /proc/self/fd/3 && echo mine""",
]
exec-pre = [["/bin/sh", "-c", "echo pre: $LISTEN_FDS"]]
env.GREETING = "hello"
"#,
        );
        assert!(matches!(test.next().await, Event::Started { .. }));
        assert!(matches!(test.next().await, Event::Exited { .. }));
        let Event::Finished { outcome, .. } = test.next().await else {
            panic!("finished expected");
        };
        assert_eq!(
            outcome,
            Outcome::Exited {
                exit: Exit::Code(0),
                tail: vec!["pre:".into(), "1 api a,b hello".into(), "mine".into()],
            },
            "only exec gets the sockets"
        );
    }

    #[tokio::test]
    async fn stubborn_processes_are_killed() {
        let mut test = Test::new();
        let handle = test.start(
            r#"
exec = ["/bin/sh", "-c", "trap '' TERM; exec {sleep} 30"]
"#,
        );
        assert!(matches!(test.next().await, Event::Started { .. }));
        tokio::time::sleep(Duration::from_millis(200)).await;
        handle.stop(/* exec_stop */ true);
        assert!(matches!(
            test.next().await,
            Event::Exited {
                exit: Exit::Signal(9),
                ..
            }
        ));
    }

    #[tokio::test]
    async fn missing_programs_fail_to_start() {
        let mut test = Test::new();
        let _handle = test.start("exec = [\"/nonexistent/program\"]\n");
        let Event::Finished { outcome, .. } = test.next().await else {
            panic!("finished expected");
        };
        let Outcome::NotStarted { reason, .. } = outcome else {
            panic!("not started expected");
        };
        assert!(
            reason.starts_with("starting /nonexistent/program: "),
            "{reason}"
        );
    }
}

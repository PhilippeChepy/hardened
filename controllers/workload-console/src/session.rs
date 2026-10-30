//! A process run in a container by `ctr tasks exec`, relayed to the call that started it.

use std::future::Future;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::unix::process::ExitStatusExt as _;
use std::path::Path;
use std::path::PathBuf;
use std::process::ExitStatus;
use std::process::Stdio;
use std::time::Duration;

use tokio::io::AsyncRead;
use tokio::io::AsyncReadExt as _;
use tokio::io::AsyncWriteExt as _;
use tokio::process::Child;
use tokio::process::ChildStderr;
use tokio::process::ChildStdin;
use tokio::process::ChildStdout;
use tokio::process::Command;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::StreamExt as _;
use tonic::Status;
use workload_console::ContainerId;
use workload_console::ExecProcess;
use workload_console::TerminalSize;
use workload_console::console::ExecInput;
use workload_console::console::ExecResponse;
use workload_console::console::exec_input;
use workload_console::console::exec_response;

use crate::pty::Pty;

const NAMESPACE: &str = "system";
/// How long `ctr` gets to report a killed process before it is killed too.
const KILL_TIMEOUT: Duration = Duration::from_secs(10);
const CHUNK: usize = 32 * 1024;

pub type Responses = mpsc::Sender<Result<ExecResponse, Status>>;

/// A process running in a container, through its `ctr`.
pub struct Session {
    ctr: PathBuf,
    container: ContainerId,
    exec_id: String,
    child: Child,
    io: Io,
}

enum Io {
    Terminal(Pty),
    Pipes {
        stdin: ChildStdin,
        stdout: ChildStdout,
        stderr: ChildStderr,
    },
}

enum Outcome {
    Exited(io::Result<ExitStatus>),
    /// The call ended first, with the error to report, if any.
    Ended(Option<Status>),
}

impl Session {
    /// Starts `process` in `container` with the program `ctr`. Within a tokio runtime.
    pub fn start(ctr: &Path, container: ContainerId, process: ExecProcess) -> io::Result<Self> {
        let exec_id = format!("console-{}", uuid::Uuid::new_v4().simple());
        let mut command = Command::new(ctr);
        command.args([
            "--namespace",
            NAMESPACE,
            "tasks",
            "exec",
            "--exec-id",
            &exec_id,
        ]);
        if process.terminal.is_some() {
            command.arg("--tty");
        }
        command
            .arg(container.as_str())
            .args(process.command.iter().map(|argument| argument.as_str()))
            .kill_on_drop(true);
        let pty = process.terminal.map(Pty::open).transpose()?;
        match &pty {
            Some((_, slave)) => {
                command
                    .stdin(slave.try_clone()?)
                    .stdout(slave.try_clone()?)
                    .stderr(slave.try_clone()?);
                // SAFETY: only system calls, async-signal-safe, no allocation.
                unsafe {
                    command.pre_exec(|| {
                        // The controlling terminal: resizing it sends `ctr` SIGWINCH, and `ctr`
                        // resizes the container's.
                        rustix::process::setsid()?;
                        // SAFETY: stdin, the slave side, is set up before this runs.
                        let stdin = BorrowedFd::borrow_raw(0);
                        rustix::process::ioctl_tiocsctty(stdin)?;
                        Ok(())
                    });
                }
            }
            None => {
                command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
        }
        let mut child = command.spawn()?;
        // Closes our copies of the slave side, so the master reads end of file when `ctr` exits.
        drop(command);
        let io = match pty {
            Some((pty, _slave)) => Io::Terminal(pty),
            None => Io::Pipes {
                stdin: child.stdin.take().expect("stdin is piped"),
                stdout: child.stdout.take().expect("stdout is piped"),
                stderr: child.stderr.take().expect("stderr is piped"),
            },
        };
        tracing::info!(%container, exec_id, "process started");
        Ok(Self {
            ctr: ctr.to_owned(),
            container,
            exec_id,
            child,
            io,
        })
    }

    /// Relays `inputs` to the process, and its output then exit code to `responses`. Kills it
    /// when `inputs` end, carry an invalid input, or `responses` close first.
    pub async fn relay(self, inputs: impl Stream<Item = ExecInput> + Unpin, responses: Responses) {
        let Self {
            ctr,
            container,
            exec_id,
            mut child,
            io,
        } = self;
        let outcome = match io {
            Io::Terminal(pty) => {
                let output = async {
                    forward_terminal(&pty, &responses).await;
                    child.wait().await
                };
                race(output, terminal_inputs(&pty, inputs), &responses).await
            }
            Io::Pipes {
                stdin,
                stdout,
                stderr,
            } => {
                let output = async {
                    tokio::join!(
                        forward(stdout, exec_response::Response::Stdout, &responses),
                        forward(stderr, exec_response::Response::Stderr, &responses),
                    );
                    child.wait().await
                };
                race(output, pipe_inputs(stdin, inputs), &responses).await
            }
        };
        let response = match outcome {
            Outcome::Exited(Ok(status)) => {
                let code = exit_code(status);
                tracing::info!(%container, exec_id, code, "process exited");
                Ok(ExecResponse {
                    response: Some(exec_response::Response::ExitCode(code)),
                })
            }
            Outcome::Exited(Err(error)) => {
                tracing::warn!(%container, exec_id, %error, "waiting for ctr failed");
                Err(Status::internal(format!("waiting for ctr: {error}")))
            }
            Outcome::Ended(status) => {
                tracing::info!(%container, exec_id, "call ended, killing the process");
                kill(&ctr, &container, &exec_id, &mut child).await;
                match status {
                    Some(status) => Err(status),
                    None => return,
                }
            }
        };
        let _ = responses.send(response).await;
    }
}

async fn race(
    output: impl Future<Output = io::Result<ExitStatus>>,
    inputs: impl Future<Output = Result<(), Status>>,
    responses: &Responses,
) -> Outcome {
    tokio::select! {
        status = output => Outcome::Exited(status),
        ended = inputs => Outcome::Ended(ended.err()),
        () = responses.closed() => Outcome::Ended(None),
    }
}

async fn forward(
    mut reader: impl AsyncRead + Unpin,
    kind: fn(Vec<u8>) -> exec_response::Response,
    responses: &Responses,
) {
    let mut buffer = vec![0; CHUNK];
    loop {
        let read = match reader.read(&mut buffer).await {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(%error, "reading the process's output failed");
                return;
            }
        };
        let response = ExecResponse {
            response: Some(kind(buffer[..read].to_vec())),
        };
        if responses.send(Ok(response)).await.is_err() {
            return;
        }
    }
}

async fn forward_terminal(pty: &Pty, responses: &Responses) {
    let mut buffer = vec![0; CHUNK];
    loop {
        let read = match pty.read(&mut buffer).await {
            Ok(0) => return,
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(%error, "reading the terminal failed");
                return;
            }
        };
        let response = ExecResponse {
            response: Some(exec_response::Response::Stdout(buffer[..read].to_vec())),
        };
        if responses.send(Ok(response)).await.is_err() {
            return;
        }
    }
}

async fn terminal_inputs(
    pty: &Pty,
    mut inputs: impl Stream<Item = ExecInput> + Unpin,
) -> Result<(), Status> {
    while let Some(input) = inputs.next().await {
        match input.input {
            Some(exec_input::Input::Stdin(data)) => {
                // Only once the process exited.
                if let Err(error) = pty.write_all(&data).await {
                    tracing::debug!(%error, "writing to the terminal failed");
                }
            }
            Some(exec_input::Input::Resize(size)) => {
                let size = TerminalSize::try_from(size)
                    .map_err(|error| Status::invalid_argument(format!("resize.{error}")))?;
                if let Err(error) = pty.resize(size) {
                    tracing::warn!(%error, "resizing the terminal failed");
                }
            }
            Some(exec_input::Input::CloseStdin(())) | None => {}
        }
    }
    Ok(())
}

async fn pipe_inputs(
    stdin: ChildStdin,
    mut inputs: impl Stream<Item = ExecInput> + Unpin,
) -> Result<(), Status> {
    let mut stdin = Some(stdin);
    while let Some(input) = inputs.next().await {
        match input.input {
            Some(exec_input::Input::Stdin(data)) => {
                let Some(pipe) = &mut stdin else {
                    return Err(Status::failed_precondition("stdin is closed"));
                };
                if let Err(error) = pipe.write_all(&data).await {
                    tracing::debug!(%error, "writing to the process failed");
                }
            }
            Some(exec_input::Input::CloseStdin(())) => stdin = None,
            Some(exec_input::Input::Resize(_)) | None => {}
        }
    }
    Ok(())
}

/// Kills the process, then `ctr` if it does not exit in time.
async fn kill(ctr: &Path, container: &ContainerId, exec_id: &str, child: &mut Child) {
    let killed = Command::new(ctr)
        .args([
            "--namespace",
            NAMESPACE,
            "tasks",
            "kill",
            "--signal",
            "SIGKILL",
        ])
        .args(["--exec-id", exec_id, container.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .status()
        .await;
    match killed {
        Ok(status) if status.success() => {}
        Ok(status) => tracing::warn!(%container, exec_id, %status, "ctr tasks kill failed"),
        Err(error) => tracing::warn!(%container, exec_id, %error, "running ctr tasks kill failed"),
    }
    if tokio::time::timeout(KILL_TIMEOUT, child.wait())
        .await
        .is_err()
    {
        tracing::warn!(%container, exec_id, "ctr did not exit, killing it");
        let _ = child.start_kill();
    }
}

/// As shells report it.
#[must_use]
fn exit_code(status: ExitStatus) -> i32 {
    status
        .code()
        .or_else(|| status.signal().map(|signal| 128 + signal))
        .unwrap_or(-1)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::OnceLock;

    use tokio_stream::wrappers::ReceiverStream;
    use workload_console::console;

    use super::*;

    /// A `ctr` running the command itself, its pid kept in a file named after the exec ID, which
    /// `tasks kill` kills.
    const FAKE_CTR: &str = r#"#!/bin/sh
dir=$(dirname "$0")
if [ "$4" = kill ]; then
    exec kill -9 "$(cat "$dir/$8")"
fi
echo $$ > "$dir/$6"
shift 6
[ "$1" = --tty ] && shift
shift
exec "$@"
"#;

    struct Test {
        dir: &'static Path,
    }

    impl Test {
        /// The fake is written once, before any test spawns: a child forked while it is open
        /// for writing would make executing it fail (ETXTBSY).
        fn new() -> Self {
            static DIR: OnceLock<tempfile::TempDir> = OnceLock::new();
            let dir = DIR.get_or_init(|| {
                let dir = tempfile::tempdir().unwrap();
                let ctr = dir.path().join("ctr");
                fs::write(&ctr, FAKE_CTR).unwrap();
                fs::set_permissions(&ctr, fs::Permissions::from_mode(0o755)).unwrap();
                dir
            });
            Self { dir: dir.path() }
        }

        fn start(
            &self,
            command: &[&str],
            terminal: Option<TerminalSize>,
        ) -> (
            mpsc::Sender<ExecInput>,
            mpsc::Receiver<Result<ExecResponse, Status>>,
            tokio::task::JoinHandle<()>,
        ) {
            let process = ExecProcess::try_from(console::Process {
                command: command.iter().map(|&argument| argument.into()).collect(),
                terminal: terminal.map(console::TerminalSize::from),
            })
            .unwrap();
            let ctr = self.dir.join("ctr");
            let session = Session::start(&ctr, "workload-web".parse().unwrap(), process).unwrap();
            let (inputs, received) = mpsc::channel(4);
            let (responses, sent) = mpsc::channel(4);
            let relay = tokio::spawn(session.relay(ReceiverStream::new(received), responses));
            (inputs, sent, relay)
        }
    }

    fn input(input: exec_input::Input) -> ExecInput {
        ExecInput { input: Some(input) }
    }

    async fn collect(
        mut responses: mpsc::Receiver<Result<ExecResponse, Status>>,
    ) -> (String, String, Option<i32>) {
        let (mut stdout, mut stderr, mut code) = (Vec::new(), Vec::new(), None);
        while let Some(response) = responses.recv().await {
            match response.unwrap().response.unwrap() {
                exec_response::Response::Stdout(data) => stdout.extend(data),
                exec_response::Response::Stderr(data) => stderr.extend(data),
                exec_response::Response::ExitCode(exit) => code = Some(exit),
            }
        }
        let text = |bytes| String::from_utf8(bytes).unwrap();
        (text(stdout), text(stderr), code)
    }

    #[tokio::test]
    async fn relays_pipes_and_the_exit_code() {
        let test = Test::new();
        let (inputs, responses, _) = test.start(&["sh", "-c", "cat; echo oops >&2; exit 3"], None);
        inputs
            .send(input(exec_input::Input::Stdin(b"hello".to_vec())))
            .await
            .unwrap();
        inputs
            .send(input(exec_input::Input::CloseStdin(())))
            .await
            .unwrap();
        let output = collect(responses).await;
        assert_eq!(output, ("hello".into(), "oops\n".into(), Some(3)));
        drop(inputs);
    }

    #[tokio::test]
    async fn runs_on_a_terminal_of_the_given_size() {
        let test = Test::new();
        let size = TerminalSize {
            rows: 24,
            columns: 100,
        };
        let (inputs, responses, _) = test.start(
            &["sh", "-c", "test -t 0 && stty size; kill -9 $$"],
            Some(size),
        );
        let (stdout, stderr, code) = collect(responses).await;
        assert_eq!(stdout, "24 100\r\n");
        assert_eq!(stderr, "");
        assert_eq!(code, Some(137));
        drop(inputs);
    }

    #[tokio::test]
    async fn kills_the_process_when_the_call_ends() {
        let test = Test::new();
        let (inputs, responses, relay) = test.start(&["sleep", "60"], None);
        drop(inputs);
        tokio::time::timeout(Duration::from_secs(5), relay)
            .await
            .expect("the process is killed")
            .unwrap();
        assert_eq!(
            collect(responses).await,
            (String::new(), String::new(), None)
        );
    }

    #[tokio::test]
    async fn rejects_invalid_resizes() {
        let test = Test::new();
        let size = TerminalSize {
            rows: 1,
            columns: 1,
        };
        let (inputs, mut responses, _) = test.start(&["sleep", "60"], Some(size));
        let resize = console::TerminalSize {
            rows: 0,
            columns: 80,
        };
        inputs
            .send(input(exec_input::Input::Resize(resize)))
            .await
            .unwrap();
        let status = responses.recv().await.unwrap().unwrap_err();
        assert_eq!(status.code(), tonic::Code::InvalidArgument);
        assert!(responses.recv().await.is_none());
    }
}

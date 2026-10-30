//! `hctl workloads exec`: a process in a workload's container, on this terminal or on pipes.

use std::io::{self, IsTerminal as _, Read as _, Write as _};
use std::process::ExitCode;
use std::thread;

use anyhow::Context as _;
use clap::Args;
use rustix::termios::{OptionalActions, Termios};
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;
use workload_console::console::{ExecInput, Process, TerminalSize, exec_input, exec_response};
use workload_controller::workloads::workloads_client::WorkloadsClient;
use workload_controller::workloads::{ExecRequest, ExecStart, exec_request};

use crate::client::CallFailed;

/// Without a terminal to measure.
const DEFAULT_SIZE: TerminalSize = TerminalSize {
    rows: 24,
    columns: 80,
};

/// `hctl workloads exec`'s arguments.
#[derive(Args)]
pub struct ExecArgs {
    name: String,
    /// Passes standard input to the process.
    #[arg(short = 'i', long)]
    stdin: bool,
    /// Runs the process on a terminal, its output all on standard output.
    #[arg(short, long)]
    tty: bool,
    /// The program and its arguments, after `--`.
    #[arg(last = true, required = true, value_name = "COMMAND")]
    command: Vec<String>,
}

/// Runs the process, exiting with its exit code.
pub async fn run(channel: Channel, args: ExecArgs) -> anyhow::Result<ExitCode> {
    let terminal = args.tty.then(terminal_size);
    let (requests, received) = mpsc::channel(16);
    let start = exec_request::Request::Start(ExecStart {
        name: args.name,
        process: Some(Process {
            command: args.command,
            terminal,
        }),
    });
    requests.send(request(start)).await?;
    let raw = if args.tty && args.stdin && io::stdin().is_terminal() {
        Some(RawMode::enable().context("setting the terminal to raw mode")?)
    } else {
        None
    };
    if args.stdin {
        // Not tokio's stdin, whose blocking read would hold the runtime's shutdown.
        let requests = requests.clone();
        thread::spawn(move || forward_stdin(&requests));
    } else if !args.tty {
        requests
            .send(input(exec_input::Input::CloseStdin(())))
            .await?;
    }
    if args.tty {
        let requests = requests.clone();
        let mut resized = signal(SignalKind::window_change()).context("handling SIGWINCH")?;
        tokio::spawn(async move {
            while resized.recv().await.is_some() {
                let resize = input(exec_input::Input::Resize(terminal_size()));
                if requests.send(resize).await.is_err() {
                    return;
                }
            }
        });
    }

    let mut responses = WorkloadsClient::new(channel)
        .exec(ReceiverStream::new(received))
        .await
        .map_err(CallFailed)?
        .into_inner();
    let mut code = None;
    while let Some(response) = responses.message().await.map_err(CallFailed)? {
        match response.response {
            Some(exec_response::Response::Stdout(data)) => {
                let mut stdout = io::stdout().lock();
                stdout.write_all(&data)?;
                stdout.flush()?;
            }
            Some(exec_response::Response::Stderr(data)) => io::stderr().lock().write_all(&data)?,
            Some(exec_response::Response::ExitCode(exit)) => code = Some(exit),
            None => {}
        }
    }
    // The requests end with the call, not before: that would kill the process.
    drop(requests);
    drop(raw);
    let code = code.context("the call ended without the process's exit code")?;
    Ok(ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX)))
}

#[must_use]
fn request(request: exec_request::Request) -> ExecRequest {
    ExecRequest {
        request: Some(request),
    }
}

#[must_use]
fn input(input: exec_input::Input) -> ExecRequest {
    request(exec_request::Request::Input(ExecInput {
        input: Some(input),
    }))
}

/// Standard output's terminal size, if it is one.
#[must_use]
fn terminal_size() -> TerminalSize {
    match rustix::termios::tcgetwinsize(io::stdout()) {
        Ok(size) if size.ws_row != 0 && size.ws_col != 0 => TerminalSize {
            rows: size.ws_row.into(),
            columns: size.ws_col.into(),
        },
        _ => DEFAULT_SIZE,
    }
}

/// Sends standard input until its end, then closes the process's.
fn forward_stdin(requests: &mpsc::Sender<ExecRequest>) {
    let mut buffer = vec![0; 32 * 1024];
    loop {
        let data = match io::stdin().read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => buffer[..read].to_vec(),
        };
        if requests
            .blocking_send(input(exec_input::Input::Stdin(data)))
            .is_err()
        {
            return;
        }
    }
    let _ = requests.blocking_send(input(exec_input::Input::CloseStdin(())));
}

/// The terminal in raw mode, every key going to the process, until dropped.
struct RawMode {
    original: Termios,
}

impl RawMode {
    fn enable() -> io::Result<Self> {
        let original = rustix::termios::tcgetattr(io::stdin())?;
        let mut raw = original.clone();
        raw.make_raw();
        rustix::termios::tcsetattr(io::stdin(), OptionalActions::Now, &raw)?;
        Ok(Self { original })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = rustix::termios::tcsetattr(io::stdin(), OptionalActions::Now, &self.original);
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(flatten)]
        args: ExecArgs,
    }

    #[test]
    fn parses_like_kubectl_exec() {
        let cli = Cli::try_parse_from(["exec", "-it", "web", "--", "sh", "-l"]).unwrap();
        assert!(cli.args.stdin && cli.args.tty);
        assert_eq!(cli.args.name, "web");
        assert_eq!(cli.args.command, ["sh", "-l"]);
        assert!(Cli::try_parse_from(["exec", "web"]).is_err());
    }
}

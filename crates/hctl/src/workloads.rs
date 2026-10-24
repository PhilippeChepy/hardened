//! Workload management.

use std::collections::HashMap;
use std::io::{self, Write};

use anyhow::bail;
use clap::{Args, Subcommand, ValueEnum};
use dust_proto::v1::workloads_client::WorkloadsClient;
use dust_proto::v1::{
    ApplyWorkloadRequest, Mount, RestartPolicy, Workload, WorkloadLogsRequest, WorkloadRef, WorkloadSource,
    WorkloadSpec,
};
use tonic::transport::Channel;

use crate::args::EnvVar;
use crate::client::{CallExt, CallFailed};

#[derive(Subcommand)]
pub enum Command {
    /// Lists workloads and their state.
    #[command(alias = "ls")]
    List,
    /// Creates or replaces a workload; it persists across reboots.
    Apply(ApplyArgs),
    /// Stops and removes a workload.
    #[command(alias = "remove")]
    Rm { name: String },
    /// Restarts a workload.
    Restart { name: String },
    /// Prints a workload's output as raw bytes.
    Logs {
        name: String,
        /// Keeps streaming new output.
        #[arg(short, long)]
        follow: bool,
        /// Number of trailing bytes to print first (0: the whole log).
        #[arg(long, default_value_t = 0)]
        tail_bytes: u64,
    },
}

#[derive(Args)]
pub struct ApplyArgs {
    name: String,
    /// Image reference, e.g. docker.io/library/nginx:1.29.
    #[arg(long)]
    image: String,
    /// Overrides the image entrypoint (repeat for each element).
    #[arg(long, allow_hyphen_values = true)]
    command: Vec<String>,
    /// Overrides the image command (repeat for each argument).
    #[arg(long = "arg", allow_hyphen_values = true)]
    args: Vec<String>,
    /// Environment variable as KEY=VALUE (repeatable).
    #[arg(long, value_name = "KEY=VALUE")]
    env: Vec<EnvVar>,
    /// Runs with all capabilities and host devices, no seccomp filter and unmasked `/proc` and `/sys`.
    #[arg(long)]
    privileged: bool,
    #[arg(long, value_enum, default_value_t = Restart::Always)]
    restart: Restart,
    /// Bind mount as SOURCE:DESTINATION[:ro] (repeatable); sources must live under /var.
    #[arg(long, value_name = "SRC:DST[:ro]", value_parser = crate::args::mount)]
    mount: Vec<Mount>,
}

#[derive(Clone, Copy, ValueEnum)]
enum Restart {
    Always,
    OnFailure,
    Never,
}

impl From<Restart> for RestartPolicy {
    fn from(restart: Restart) -> Self {
        match restart {
            Restart::Always => Self::Always,
            Restart::OnFailure => Self::OnFailure,
            Restart::Never => Self::Never,
        }
    }
}

impl ApplyArgs {
    fn into_request(self) -> anyhow::Result<ApplyWorkloadRequest> {
        let mut env = HashMap::with_capacity(self.env.len());
        for EnvVar { key, value } in self.env {
            if env.insert(key.clone(), value).is_some() {
                bail!("--env {key} given more than once");
            }
        }
        let mut spec = WorkloadSpec {
            image: self.image,
            command: self.command,
            args: self.args,
            env,
            privileged: self.privileged,
            mounts: self.mount,
            ..Default::default()
        };
        spec.set_restart(self.restart.into());
        Ok(ApplyWorkloadRequest {
            name: self.name,
            spec: Some(spec),
        })
    }
}

pub async fn run(channel: Channel, command: Command) -> anyhow::Result<()> {
    let mut client = WorkloadsClient::new(channel);
    match command {
        Command::List => {
            let list = client.list(()).await.into_result()?;
            print_table(&mut io::stdout().lock(), &list.workloads)?;
        }
        Command::Apply(args) => {
            let workload = client.apply(args.into_request()?).await.into_result()?;
            eprintln!("{}: {}", workload.name, StateColumns::of(&workload).state);
        }
        Command::Rm { name } => {
            client.remove(WorkloadRef { name }).await.into_result()?;
        }
        Command::Restart { name } => {
            client.restart(WorkloadRef { name }).await.into_result()?;
        }
        Command::Logs {
            name,
            follow,
            tail_bytes,
        } => {
            let request = WorkloadLogsRequest {
                name,
                follow,
                tail_bytes,
            };
            let mut chunks = client.logs(request).await.into_result()?;
            let mut out = io::stdout().lock();
            while let Some(chunk) = chunks.message().await.map_err(CallFailed)? {
                out.write_all(&chunk.data)?;
                out.flush()?;
            }
        }
    }
    Ok(())
}

fn print_table(out: &mut impl Write, workloads: &[Workload]) -> io::Result<()> {
    const HEADERS: [&str; 8] = ["NAME", "IMAGE", "SOURCE", "STATE", "PID", "RESTARTS", "EXIT", "MESSAGE"];
    let rows: Vec<[String; 8]> = workloads.iter().map(row).collect();
    let mut widths = HEADERS.map(str::len);
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let header = HEADERS.map(str::to_owned);
    for cells in std::iter::once(&header).chain(&rows) {
        let mut line = String::new();
        for (i, (cell, width)) in cells.iter().zip(widths).enumerate() {
            if i + 1 == cells.len() {
                line.push_str(cell);
            } else {
                line.push_str(&format!("{cell:<width$}  "));
            }
        }
        writeln!(out, "{}", line.trim_end())?;
    }
    Ok(())
}

fn row(w: &Workload) -> [String; 8] {
    let source = match w.source() {
        WorkloadSource::UserData => "user-data",
        WorkloadSource::Api => "api",
        WorkloadSource::Unspecified => "-",
    };
    let columns = StateColumns::of(w);
    [
        w.name.clone(),
        w.spec.as_ref().map(|s| s.image.clone()).unwrap_or_default(),
        source.into(),
        columns.state.into(),
        columns.pid,
        w.restarts.to_string(),
        columns.exit,
        columns.message,
    ]
}

/// The table columns derived from a workload's state.
struct StateColumns {
    state: &'static str,
    pid: String,
    exit: String,
    message: String,
}

impl StateColumns {
    fn of(w: &Workload) -> Self {
        use dust_proto::v1::workload::State;
        let dash = || "-".to_owned();
        let (state, pid, exit, message) = match &w.state {
            Some(State::Pending(_)) => ("pending", dash(), dash(), String::new()),
            Some(State::Pulling(_)) => ("pulling", dash(), dash(), String::new()),
            Some(State::Running(running)) => ("running", running.pid.to_string(), dash(), String::new()),
            Some(State::Exited(exited)) => ("exited", dash(), exited.exit_code.to_string(), String::new()),
            Some(State::Failed(failed)) => ("failed", dash(), dash(), failed.reason.clone()),
            None => ("unknown", dash(), dash(), String::new()),
        };
        Self {
            state,
            pid,
            exit,
            message,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct Cli {
        #[command(subcommand)]
        command: Command,
    }

    fn apply(args: &[&str]) -> anyhow::Result<ApplyWorkloadRequest> {
        let cli = Cli::try_parse_from(["workloads", "apply"].iter().chain(args))?;
        let Command::Apply(args) = cli.command else {
            unreachable!()
        };
        args.into_request()
    }

    #[test]
    fn builds_apply_requests() {
        let request = apply(&[
            "web",
            "--image",
            "nginx",
            "--command",
            "/bin/sh",
            "--arg",
            "-c",
            "--arg",
            "exec nginx",
            "--env",
            "A=1",
            "--env",
            "B=x=y",
            "--restart",
            "on-failure",
            "--mount",
            "/var/www:/www:ro",
            "--privileged",
        ])
        .unwrap();
        assert_eq!(request.name, "web");
        let spec = request.spec.unwrap();
        assert_eq!(spec.image, "nginx");
        assert_eq!(spec.command, ["/bin/sh"]);
        assert_eq!(spec.args, ["-c", "exec nginx"]);
        assert_eq!(spec.env.len(), 2);
        assert_eq!(spec.env["B"], "x=y");
        assert_eq!(spec.restart(), RestartPolicy::OnFailure);
        assert!(spec.privileged);
        assert_eq!(spec.mounts.len(), 1);
        assert!(spec.mounts[0].read_only);
    }

    #[test]
    fn rejects_bad_apply_arguments() {
        assert!(apply(&["web", "--image", "nginx", "--env", "A=1", "--env", "A=2"]).is_err());
        assert!(apply(&["web", "--image", "nginx", "--env", "A"]).is_err());
        assert!(apply(&["web", "--image", "nginx", "--restart", "sometimes"]).is_err());
        assert!(apply(&["web"]).is_err());
    }
}

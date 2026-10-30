//! Workload management.

use std::collections::HashMap;
use std::io::{self, Write};
use std::process::ExitCode;

use anyhow::bail;
use clap::{Args, Subcommand, ValueEnum};
use tonic::transport::Channel;
use workload_controller::workloads::workloads_client::WorkloadsClient;
use workload_controller::workloads::{
    ApplyWorkloadRequest, Mount, Privileged, RestartPolicy, Workload, WorkloadLogsRequest,
    WorkloadRef, WorkloadSource, WorkloadSpec,
};

use crate::args::EnvVar;
use crate::client::{CallExt, CallFailed};
use crate::exec::{self, ExecArgs};
use crate::table;

/// The `hctl workloads` subcommands.
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
    /// Prints a workload's output.
    Logs {
        name: String,
        /// Keeps streaming new output.
        #[arg(short, long)]
        follow: bool,
        /// Number of past lines to print first (0: all retained).
        #[arg(long, default_value_t = 0)]
        tail: u32,
    },
    /// Runs a command in a running workload's container, exiting with its exit code.
    Exec(ExecArgs),
}

/// `hctl workloads apply`'s arguments.
#[derive(Args)]
pub struct ApplyArgs {
    name: String,
    /// Image reference, e.g. docker.io/library/nginx:1.29.
    #[arg(long)]
    image: String,
    /// The program and its arguments, after `--`, replacing the image's entrypoint and command.
    #[arg(last = true, value_name = "COMMAND")]
    command: Vec<String>,
    /// Environment variable as KEY=VALUE (repeatable).
    #[arg(long, value_name = "KEY=VALUE")]
    env: Vec<EnvVar>,
    /// Runs with all capabilities and host devices, no seccomp filter and unmasked `/proc` and
    /// `/sys`.
    #[arg(long)]
    privileged: bool,
    /// Mounts the host's / at PATH in the container, recursively read-only.
    #[arg(long, value_name = "PATH", requires = "privileged")]
    host_root: Option<String>,
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
    /// The request applying the workload, if its arguments are consistent.
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
            env,
            privileged: self.privileged.then(|| Privileged {
                host_root: self.host_root.unwrap_or_default(),
            }),
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

/// Runs an `hctl workloads` subcommand on `channel`, and the code to exit with.
pub async fn run(channel: Channel, command: Command) -> anyhow::Result<ExitCode> {
    let mut client = WorkloadsClient::new(channel.clone());
    match command {
        Command::Exec(args) => return exec::run(channel, args).await,
        Command::List => {
            let list = client.list(()).await.into_result()?;
            print_table(&mut io::stdout().lock(), &list.workloads)?;
        }
        Command::Apply(args) => {
            let workload = client.apply(args.into_request()?).await.into_result()?;
            eprintln!("{}: {}", workload.name, state(&workload));
        }
        Command::Rm { name } => {
            client.remove(WorkloadRef { name }).await.into_result()?;
        }
        Command::Restart { name } => {
            client.restart(WorkloadRef { name }).await.into_result()?;
        }
        Command::Logs { name, follow, tail } => {
            let request = WorkloadLogsRequest { name, follow, tail };
            let mut chunks = client.logs(request).await.into_result()?;
            let mut out = io::stdout().lock();
            while let Some(chunk) = chunks.message().await.map_err(CallFailed)? {
                out.write_all(&chunk.data)?;
                out.flush()?;
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

/// Prints `workloads` as a table, one row each.
fn print_table(out: &mut impl Write, workloads: &[Workload]) -> io::Result<()> {
    let header = ["NAME", "SOURCE", "RESTARTS", "IMAGE", "STATE"];
    table::print(out, header, workloads.iter().map(row))
}

/// The table row of `workload`.
#[must_use]
fn row(workload: &Workload) -> [String; 5] {
    let source = match workload.source() {
        WorkloadSource::UserData => "user-data",
        WorkloadSource::Api => "api",
        WorkloadSource::Unspecified => "-",
    };
    [
        workload.name.clone(),
        source.to_owned(),
        workload.restarts.to_string(),
        workload
            .spec
            .as_ref()
            .map(|spec| spec.image.clone())
            .unwrap_or_default(),
        state(workload),
    ]
}

/// A workload's state, with what is only meaningful in it.
#[must_use]
fn state(workload: &Workload) -> String {
    use workload_controller::workloads::workload::State;

    match &workload.state {
        Some(State::Pending(_)) => "pending".to_owned(),
        Some(State::Pulling(_)) => "pulling".to_owned(),
        Some(State::Running(running)) => format!("running, pid {}", running.pid),
        Some(State::Exited(exited)) => format!("exited with {}", exited.exit_code),
        Some(State::Failed(failed)) => format!("failed: {}", failed.reason),
        None => "unknown".to_owned(),
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
            unreachable!("the command line starts with `apply`")
        };
        args.into_request()
    }

    #[test]
    fn builds_apply_requests() {
        let request = apply(&[
            "web",
            "--image",
            "nginx",
            "--env",
            "A=1",
            "--env",
            "B=x=y",
            "--restart",
            "on-failure",
            "--mount",
            "/var/www:/www:ro",
            "--privileged",
            "--host-root",
            "/host",
            "--",
            "/bin/sh",
            "-c",
            "exec nginx",
        ])
        .unwrap();
        assert_eq!(request.name, "web");
        let spec = request.spec.unwrap();
        assert_eq!(spec.image, "nginx");
        assert_eq!(spec.command, ["/bin/sh", "-c", "exec nginx"]);
        assert_eq!(spec.env.len(), 2);
        assert_eq!(spec.env["B"], "x=y");
        assert_eq!(spec.restart(), RestartPolicy::OnFailure);
        assert_eq!(spec.privileged.unwrap().host_root, "/host");
        assert_eq!(spec.mounts.len(), 1);
        assert!(spec.mounts[0].read_only);
    }

    #[test]
    fn prints_a_table() {
        use workload_controller::workloads::workload::{Failed, Running, State};

        let workload = |name: &str, state| Workload {
            name: name.into(),
            spec: Some(WorkloadSpec {
                image: "docker.io/library/nginx:1.29".into(),
                ..WorkloadSpec::default()
            }),
            source: WorkloadSource::Api.into(),
            restarts: 2,
            state: Some(state),
        };
        let workloads = [
            workload("web", State::Running(Running { pid: 42 })),
            workload(
                "database",
                State::Failed(Failed {
                    reason: "exit code 1".into(),
                }),
            ),
        ];
        let mut out = Vec::new();
        print_table(&mut out, &workloads).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "NAME      SOURCE  RESTARTS  IMAGE                         STATE\n\
             web       api     2         docker.io/library/nginx:1.29  running, pid 42\n\
             database  api     2         docker.io/library/nginx:1.29  failed: exit code 1\n"
        );
    }

    #[test]
    fn rejects_duplicate_env_vars() {
        assert!(apply(&["web", "--image", "nginx", "--env", "A=1", "--env", "A=2"]).is_err());
    }
}

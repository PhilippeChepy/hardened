//! `hctl service`: serviced's services.

use std::io::{self, Write};

use clap::Subcommand;
use libserviced::api::Layer;
use machine_controller::services::service::LastExit;
use machine_controller::services::services_client::ServicesClient;
use machine_controller::services::{LogsRequest, Service, ServiceRef};
use tonic::transport::Channel;

use crate::client::{CallExt, CallFailed};
use crate::table;

/// The `hctl service` subcommands.
#[derive(Subcommand)]
pub enum Command {
    /// Lists the services and their state.
    #[command(alias = "ls")]
    List,
    /// Shows a service in detail.
    Status { name: String },
    /// Starts a stopped, exited or failed service.
    Start { name: String },
    /// Stops a service until it is started again or the machine reboots.
    Stop { name: String },
    /// Restarts a service.
    Restart { name: String },
    /// Re-reads the service files and reconciles.
    Reload,
    /// Prints a service's output.
    Logs {
        name: String,
        /// Keeps streaming new output.
        #[arg(short, long)]
        follow: bool,
        /// Number of past lines to print first (0: all retained).
        #[arg(long, default_value_t = 0)]
        tail: u32,
    },
}

/// Runs an `hctl service` subcommand on `channel`.
pub async fn run(channel: Channel, command: Command) -> anyhow::Result<()> {
    let mut client = ServicesClient::new(channel);
    let mut out = io::stdout().lock();
    match command {
        Command::List => {
            let services = client.list(()).await.into_result()?.services;
            let header = ["NAME", "STATE", "PID", "RESTARTS", "DESCRIPTION"];
            table::print(&mut out, header, services.iter().map(row))?;
        }
        Command::Status { name } => {
            let service = client.get(ServiceRef { name }).await.into_result()?;
            for line in status_lines(&service) {
                writeln!(out, "{line}")?;
            }
        }
        Command::Start { name } => client.start(ServiceRef { name }).await.into_result()?,
        Command::Stop { name } => client.stop(ServiceRef { name }).await.into_result()?,
        Command::Restart { name } => client.restart(ServiceRef { name }).await.into_result()?,
        Command::Reload => {
            for invalid in client.reload(()).await.into_result()?.invalid {
                eprintln!("left out: {invalid}");
            }
        }
        Command::Logs { name, follow, tail } => {
            let request = LogsRequest { name, follow, tail };
            let mut lines = client.logs(request).await.into_result()?;
            while let Some(line) = lines.message().await.map_err(CallFailed)? {
                let time = line
                    .time
                    .map_or_else(|| "-".to_owned(), |time| time.to_string());
                writeln!(out, "{time} {}", line.text)?;
                out.flush()?;
            }
        }
    }
    Ok(())
}

/// `STATE_READY` as `ready`.
#[must_use]
fn state(service: &Service) -> String {
    let state = service.state();
    let name = state.as_str_name();
    name.strip_prefix("STATE_").unwrap_or(name).to_lowercase()
}

#[must_use]
fn row(service: &Service) -> [String; 5] {
    [
        service.name.clone(),
        state(service),
        service
            .pid
            .map_or_else(|| "-".to_owned(), |pid| pid.to_string()),
        service.restarts.to_string(),
        service.description.clone(),
    ]
}

/// `hctl service status`'s lines, those without a value left out.
#[must_use]
fn status_lines(service: &Service) -> Vec<String> {
    let mut state = state(service);
    if let Some(since) = &service.since {
        state.push_str(&format!(" since {since}"));
    }
    if let Some(pid) = service.pid {
        state.push_str(&format!(", pid {pid}"));
    }
    let layers: Vec<&str> = service
        .layers()
        .map(|layer| match layer {
            Layer::Image => "image",
            Layer::Runtime => "runtime",
            Layer::Persistent => "persistent",
            Layer::Unspecified => "-",
        })
        .collect();
    let last_exit = match service.last_exit {
        Some(LastExit::ExitCode(code)) => format!("exit code {code}"),
        Some(LastExit::Signal(signal)) => format!("signal {signal}"),
        None => String::new(),
    };
    let sandbox = service
        .user
        .map_or_else(|| "none".to_owned(), |user| format!("uid {user}"));
    [
        ("Name:", service.name.clone()),
        ("Description:", service.description.clone()),
        ("State:", state),
        (
            "Enabled:",
            if service.enabled { "yes" } else { "no" }.to_owned(),
        ),
        ("Layers:", layers.join(", ")),
        ("Requires:", service.requires.join(", ")),
        ("Sandbox:", sandbox),
        ("Restarts:", service.restarts.to_string()),
        ("Last exit:", last_exit),
        ("Reason:", service.reason.clone()),
        ("Status:", service.status_text.clone()),
    ]
    .into_iter()
    .filter(|(_, value)| !value.is_empty())
    .map(|(label, value)| format!("{label:<13} {value}"))
    .collect()
}

#[cfg(test)]
mod tests {
    use libserviced::api::State;

    use super::*;

    #[test]
    fn shows_a_service() {
        let mut service = Service {
            name: "containerd".into(),
            description: "the container runtime".into(),
            enabled: true,
            layers: vec![Layer::Image.into(), Layer::Runtime.into()],
            requires: vec!["storage-controller".into()],
            pid: Some(42),
            restarts: 1,
            last_exit: Some(LastExit::Signal(9)),
            ..Service::default()
        };
        service.set_state(State::Ready);
        assert_eq!(
            status_lines(&service),
            [
                "Name:         containerd",
                "Description:  the container runtime",
                "State:        ready, pid 42",
                "Enabled:      yes",
                "Layers:       image, runtime",
                "Requires:     storage-controller",
                "Sandbox:      none",
                "Restarts:     1",
                "Last exit:    signal 9",
            ]
        );
        let mut out = Vec::new();
        table::print(
            &mut out,
            ["NAME", "STATE", "PID", "RESTARTS", "DESCRIPTION"],
            [row(&service)],
        )
        .unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "NAME        STATE  PID  RESTARTS  DESCRIPTION\n\
             containerd  ready  42   1         the container runtime\n"
        );
    }
}

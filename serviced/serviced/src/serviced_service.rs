//! serviced's API (`hardened.serviced.v1.Serviced`): each call is allowed if the calling
//! service's `api` grants what its method needs ([`Method::access`]), refused with
//! `PERMISSION_DENIED` otherwise. `IdentifyProcess` is open to every service.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use libserviced::api;
use libserviced::api::serviced_server::Serviced;
use libserviced::definition::{Access, ServiceName};
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::caller::{Caller, Resolver};
use crate::command::Command;
use crate::engine::Refusal;
use crate::exit::Exit;
use crate::log_buffer::{LogEntry, Poisoned};
use crate::log_store::LogStore;
use crate::method::Method;
use crate::overview::{Overview, ServiceView};
use crate::power::PowerRequest;
use crate::service_status::State;
use crate::shutdown_locks::ShutdownLocks;

/// Lines queued for a streaming client.
const STREAM_QUEUE: usize = 64;

/// What serviced's API reads and acts on.
pub struct ServicedService {
    pub overview: Arc<Overview>,
    pub logs: Arc<LogStore>,
    /// Finds the service of a process, for `IdentifyProcess`.
    pub resolve: Resolver,
    /// To the supervisor.
    pub commands: mpsc::UnboundedSender<Command>,
    pub power: mpsc::Sender<PowerRequest>,
    /// The delay locks `WatchShutdown` takes, which the supervisor waits for.
    pub shutdown_locks: Arc<ShutdownLocks>,
}

impl ServicedService {
    /// Whether the service calling `method` has an `api` granting what the method needs.
    async fn authorize<T>(&self, request: &Request<T>, method: Method) -> Result<(), Status> {
        let caller = request
            .extensions()
            .get::<Caller>()
            .unwrap_or(&Caller::Unknown);
        let access = method.access();
        match caller.service() {
            Some(service) if self.overview.grants(service, access, caller.uid()).await => {
                // What changes something; reads would flood the log.
                if access == Some(Access::Control) {
                    info!(caller = %caller, ?method, "API call");
                }
                Ok(())
            }
            _ => {
                warn!(caller = %caller, ?method, ?access, "API call refused");
                let needs = match access {
                    Some(access) => format!("{access:?} access"),
                    None => "a service".to_owned(),
                };
                Err(Status::permission_denied(format!(
                    "{method:?} needs {needs}, which the caller does not have"
                )))
            }
        }
    }

    /// Asks the supervisor for `command`, made with the reply's sender, and waits for its reply.
    async fn ask<T>(
        &self,
        command: impl FnOnce(oneshot::Sender<T>) -> Command,
    ) -> Result<T, Status> {
        let (reply, replied) = oneshot::channel();
        self.commands
            .send(command(reply))
            .map_err(|_| Status::unavailable("serviced's supervisor is gone"))?;
        replied
            .await
            .map_err(|_| Status::unavailable("serviced's supervisor is gone"))
    }

    /// Starts, stops or restarts a service.
    async fn act(
        &self,
        request: Request<api::ServiceRef>,
        method: Method,
        command: fn(ServiceName, oneshot::Sender<Result<(), Refusal>>) -> Command,
    ) -> Result<Response<()>, Status> {
        self.authorize(&request, method).await?;
        let name = service_name(&request.get_ref().name)?;
        match self.ask(|reply| command(name, reply)).await? {
            Ok(()) => Ok(Response::new(())),
            Err(Refusal::Unknown) => Err(Status::not_found(format!(
                "no service {}",
                request.get_ref().name
            ))),
            Err(Refusal::ShuttingDown) => {
                Err(Status::unavailable(Refusal::ShuttingDown.to_string()))
            }
        }
    }

    async fn power(&self, request: PowerRequest) -> Result<Response<()>, Status> {
        self.power
            .send(request)
            .await
            .map_err(|_| Status::unavailable("serviced's power handling is gone"))?;
        Ok(Response::new(()))
    }
}

#[tonic::async_trait]
impl Serviced for ServicedService {
    async fn list_services(
        &self,
        request: Request<()>,
    ) -> Result<Response<api::ListServicesResponse>, Status> {
        self.authorize(&request, Method::ListServices).await?;
        let services = self
            .overview
            .services()
            .await
            .iter()
            .map(|(name, service)| service_message(name, service))
            .collect();
        Ok(Response::new(api::ListServicesResponse { services }))
    }

    async fn get_service(
        &self,
        request: Request<api::ServiceRef>,
    ) -> Result<Response<api::Service>, Status> {
        self.authorize(&request, Method::GetService).await?;
        let name = service_name(&request.get_ref().name)?;
        let service = self
            .overview
            .service(&name)
            .await
            .ok_or_else(|| Status::not_found(format!("no service {name}")))?;
        Ok(Response::new(service_message(&name, &service)))
    }

    async fn start(&self, request: Request<api::ServiceRef>) -> Result<Response<()>, Status> {
        self.act(request, Method::Start, Command::Start).await
    }

    async fn stop(&self, request: Request<api::ServiceRef>) -> Result<Response<()>, Status> {
        self.act(request, Method::Stop, Command::Stop).await
    }

    async fn restart(&self, request: Request<api::ServiceRef>) -> Result<Response<()>, Status> {
        self.act(request, Method::Restart, Command::Restart).await
    }

    async fn reload(&self, request: Request<()>) -> Result<Response<api::ReloadResponse>, Status> {
        self.authorize(&request, Method::Reload).await?;
        // Once answered, the services' sockets are as their files say.
        let invalid = self.ask(Command::Reload).await?;
        Ok(Response::new(api::ReloadResponse { invalid }))
    }

    /// Fed by a task of its own.
    type LogsStream = Pin<Box<dyn Stream<Item = Result<api::LogLine, Status>> + Send>>;

    async fn logs(
        &self,
        request: Request<api::LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        self.authorize(&request, Method::Logs).await?;
        let logs = request.into_inner();
        let log = if logs.service.is_empty() {
            self.logs.serviced().clone()
        } else {
            let name = service_name(&logs.service)?;
            match self.logs.get(&name).await {
                Some(log) => log,
                None if self.overview.service(&name).await.is_some() => {
                    self.logs.service(&name).await
                }
                None => return Err(Status::not_found(format!("no service {name}"))),
            }
        };
        let tail = usize::try_from(logs.tail).unwrap_or(usize::MAX);
        let poisoned = |e: Poisoned| Status::internal(e.to_string());
        let (past, new) = if logs.follow {
            let (past, new) = log.follow(tail).map_err(poisoned)?;
            (past, Some(new))
        } else {
            (log.tail(tail).map_err(poisoned)?, None)
        };
        let (sender, lines) = mpsc::channel(STREAM_QUEUE);
        tokio::spawn(stream_log(past, new, sender));
        Ok(Response::new(Box::pin(ReceiverStream::new(lines))))
    }

    async fn reboot(&self, request: Request<()>) -> Result<Response<()>, Status> {
        self.authorize(&request, Method::Reboot).await?;
        self.power(PowerRequest::Reboot).await
    }

    async fn power_off(&self, request: Request<()>) -> Result<Response<()>, Status> {
        self.authorize(&request, Method::PowerOff).await?;
        self.power(PowerRequest::PowerOff).await
    }

    type WatchShutdownStream =
        Pin<Box<dyn Stream<Item = Result<api::ShutdownEvent, Status>> + Send>>;

    async fn watch_shutdown(
        &self,
        request: Request<api::ShutdownLock>,
    ) -> Result<Response<Self::WatchShutdownStream>, Status> {
        self.authorize(&request, Method::WatchShutdown).await?;
        let delay = request.into_inner().delay_seconds;
        if delay == 0 {
            return Err(Status::invalid_argument("delay_seconds: 0"));
        }
        let lock = self.shutdown_locks.lock(Duration::from_secs(delay.into()));
        let (sender, events) = mpsc::channel(1);
        // The lock is held until the caller closes the stream.
        tokio::spawn(async move {
            let event = |shutting_down| Ok(api::ShutdownEvent { shutting_down });
            if !lock.announced() {
                if sender.send(event(false)).await.is_err() {
                    return;
                }
                tokio::select! {
                    () = lock.wait_announced() => {}
                    () = sender.closed() => return,
                }
            }
            if sender.send(event(true)).await.is_ok() {
                sender.closed().await;
            }
            drop(lock);
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(events))))
    }

    async fn identify_process(
        &self,
        request: Request<api::ProcessRef>,
    ) -> Result<Response<api::ServiceRef>, Status> {
        self.authorize(&request, Method::IdentifyProcess).await?;
        let pid = request.get_ref().pid;
        if pid == 0 {
            return Err(Status::invalid_argument("no pid"));
        }
        // A read of `/proc`, which does not block.
        match (self.resolve)(pid) {
            Some(service) => Ok(Response::new(api::ServiceRef {
                name: service.to_string(),
            })),
            None => Err(Status::not_found(format!(
                "process {pid} belongs to no service"
            ))),
        }
    }
}

/// Sends the `past` lines of a log, then the `new` ones if following, until the client goes.
async fn stream_log(
    past: Vec<Arc<LogEntry>>,
    new: Option<broadcast::Receiver<Arc<LogEntry>>>,
    sender: mpsc::Sender<Result<api::LogLine, Status>>,
) {
    for line in past {
        if sender.send(Ok(log_line(&line))).await.is_err() {
            return;
        }
    }
    let Some(mut new) = new else {
        return;
    };
    loop {
        let line = tokio::select! {
            () = sender.closed() => return,
            line = new.recv() => line,
        };
        let line = match line {
            Ok(line) => log_line(&line),
            Err(broadcast::error::RecvError::Lagged(skipped)) => api::LogLine {
                text: format!("[{skipped} lines skipped: the client is too slow]"),
                ..api::LogLine::default()
            },
            Err(broadcast::error::RecvError::Closed) => return,
        };
        if sender.send(Ok(line)).await.is_err() {
            return;
        }
    }
}

#[must_use]
fn log_line(entry: &LogEntry) -> api::LogLine {
    api::LogLine {
        time: entry.time.map(Into::into),
        level: entry.level.to_owned(),
        target: entry.target.to_owned(),
        text: entry.text.clone(),
    }
}

/// Service `name`'s name; no service has an invalid one.
fn service_name(name: &str) -> Result<ServiceName, Status> {
    name.parse()
        .map_err(|_| Status::not_found(format!("no service {name:?}")))
}

#[must_use]
fn service_message(name: &ServiceName, service: &ServiceView) -> api::Service {
    let definition = &service.definition;
    let status = &service.status;
    let layers = service
        .layers
        .iter()
        .map(|layer| i32::from(api::Layer::from(*layer)))
        .collect();
    let state = match status.state {
        State::Inactive => api::State::Inactive,
        State::Waiting => api::State::Waiting,
        State::Starting => api::State::Starting,
        State::Running => api::State::Running,
        State::Ready => api::State::Ready,
        State::Exited => api::State::Exited,
        State::Failed => api::State::Failed,
        State::Backoff => api::State::Backoff,
        State::Stopping => api::State::Stopping,
        State::Stopped => api::State::Stopped,
    };
    let last_exit = status.last_exit.map(|exit| api::Exit {
        how: Some(match exit {
            Exit::Code(code) => api::exit::How::Code(code),
            Exit::Signal(signal) => api::exit::How::Signal(signal),
        }),
    });
    api::Service {
        name: name.to_string(),
        description: definition.description.clone(),
        enabled: definition.enabled,
        layers,
        definition: toml::to_string(definition.as_ref()).unwrap_or_default(),
        user: definition.sandbox.as_ref().map(|sandbox| sandbox.user),
        state: state.into(),
        since: Some(status.since.into()),
        pid: status.pid,
        restarts: status.restarts,
        last_exit,
        reason: status.reason.clone().unwrap_or_default(),
        status_text: status.status_text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use libserviced::definition::{Layer, Service};

    use super::*;
    use crate::service_status::ServiceStatus;

    #[test]
    fn services_show_their_definition_as_toml() {
        let text = r#"
description = "time-controller"
exec = ["/usr/bin/time-controller"]
notify = true
api = ["read"]
console = true
runtime-directories = ["/run/x"]
env.A = "b"
meta.owner = "api"
[[sockets]]
name = "api"
path = "/run/x/api.sock"
allow = ["machine-controller"]
[sandbox]
user = 65533
syscalls = ["bind"]
limits.memory-mib = 32
limits.tasks = 4
limits.cpu-millicores = 100
[[sandbox.binds]]
path = "/etc"
"#;
        let definition: Service = toml::from_str(text).unwrap();
        let view = ServiceView {
            definition: Arc::new(definition.clone()),
            layers: vec![Layer::Image, Layer::Persistent],
            status: ServiceStatus {
                pid: Some(12),
                last_exit: Some(Exit::Signal(9)),
                status_text: "synchronized".into(),
                ..ServiceStatus::new(State::Running)
            },
        };
        let service = service_message(&"time-controller".parse().unwrap(), &view);
        let shown: Service = toml::from_str(&service.definition).unwrap();
        assert_eq!(shown, definition, "{}", service.definition);
        assert_eq!(
            service.layers().collect::<Vec<_>>(),
            [api::Layer::Image, api::Layer::Persistent]
        );
        assert_eq!(service.user, Some(65533));
        assert_eq!(service.state(), api::State::Running);
        assert_eq!(service.pid, Some(12));
        assert_eq!(
            service.last_exit.unwrap().how,
            Some(api::exit::How::Signal(9))
        );
        assert_eq!(service.status_text, "synchronized");
    }
}

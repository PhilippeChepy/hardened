//! `hardened.services.v1.Services`: serviced's services, from its API, without their definitions
//! as TOML.

use std::pin::Pin;

use libserviced::api;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::client;
use libserviced::definition;
use libserviced::definition::ServiceName;
use machine_controller::services;
use machine_controller::services::services_server::Services;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Channel;

/// Serves `Services` from `serviced`.
pub struct ServicesService {
    serviced: ServicedClient<Channel>,
}

impl ServicesService {
    #[must_use]
    pub fn new(serviced: Channel) -> Self {
        Self {
            serviced: ServicedClient::new(serviced),
        }
    }

    fn serviced(&self) -> ServicedClient<Channel> {
        self.serviced.clone()
    }
}

/// serviced's ref to the service `request` names, if valid.
fn service_ref(request: Request<services::ServiceRef>) -> Result<api::ServiceRef, Status> {
    let name = request.into_inner().name;
    name.parse::<ServiceName>()
        .map_err(|error| Status::invalid_argument(error.to_string()))?;
    Ok(api::ServiceRef { name })
}

/// serviced's `NOT_FOUND` passes through, as the caller named the service.
fn call_error(call: &str, status: Status) -> Status {
    if status.code() == Code::NotFound {
        status
    } else {
        client::call_error(call, status)
    }
}

/// The API's view of a service, its definition parsed for what it requires.
#[must_use]
fn to_proto(service: api::Service) -> services::Service {
    let requires = toml::from_str::<definition::Service>(&service.definition)
        .map(|definition| {
            definition
                .requires
                .iter()
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let last_exit = service
        .last_exit
        .and_then(|exit| exit.how)
        .map(|how| match how {
            api::exit::How::Code(code) => services::service::LastExit::ExitCode(code),
            api::exit::How::Signal(signal) => services::service::LastExit::Signal(signal),
        });
    services::Service {
        name: service.name,
        description: service.description,
        enabled: service.enabled,
        layers: service.layers,
        requires,
        user: service.user,
        state: service.state,
        since: service.since,
        pid: service.pid,
        restarts: service.restarts,
        last_exit,
        reason: service.reason,
        status_text: service.status_text,
    }
}

#[tonic::async_trait]
impl Services for ServicesService {
    async fn list(
        &self,
        _: Request<()>,
    ) -> Result<Response<services::ListServicesResponse>, Status> {
        let list = self
            .serviced()
            .list_services(())
            .await
            .map_err(|status| call_error("ListServices", status))?
            .into_inner();
        let services = list.services.into_iter().map(to_proto).collect();
        Ok(Response::new(services::ListServicesResponse { services }))
    }

    async fn get(
        &self,
        request: Request<services::ServiceRef>,
    ) -> Result<Response<services::Service>, Status> {
        let service = self
            .serviced()
            .get_service(service_ref(request)?)
            .await
            .map_err(|status| call_error("GetService", status))?
            .into_inner();
        Ok(Response::new(to_proto(service)))
    }

    async fn start(&self, request: Request<services::ServiceRef>) -> Result<Response<()>, Status> {
        let request = service_ref(request)?;
        tracing::info!(service = request.name, "start requested");
        self.serviced()
            .start(request)
            .await
            .map_err(|status| call_error("Start", status))
    }

    async fn stop(&self, request: Request<services::ServiceRef>) -> Result<Response<()>, Status> {
        let request = service_ref(request)?;
        tracing::info!(service = request.name, "stop requested");
        self.serviced()
            .stop(request)
            .await
            .map_err(|status| call_error("Stop", status))
    }

    async fn restart(
        &self,
        request: Request<services::ServiceRef>,
    ) -> Result<Response<()>, Status> {
        let request = service_ref(request)?;
        tracing::info!(service = request.name, "restart requested");
        self.serviced()
            .restart(request)
            .await
            .map_err(|status| call_error("Restart", status))
    }

    async fn reload(&self, _: Request<()>) -> Result<Response<services::ReloadResponse>, Status> {
        tracing::info!("reload requested");
        let reloaded = self
            .serviced()
            .reload(())
            .await
            .map_err(|status| call_error("Reload", status))?
            .into_inner();
        Ok(Response::new(services::ReloadResponse {
            invalid: reloaded.invalid,
        }))
    }

    type LogsStream = Pin<Box<dyn Stream<Item = Result<services::LogLine, Status>> + Send>>;

    async fn logs(
        &self,
        request: Request<services::LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let services::LogsRequest { name, follow, tail } = request.into_inner();
        let service = service_ref(Request::new(services::ServiceRef { name }))?.name;
        let request = api::LogsRequest {
            service,
            tail,
            follow,
        };
        let lines = self
            .serviced()
            .logs(request)
            .await
            .map_err(|status| call_error("Logs", status))?
            .into_inner();
        let lines = lines.map(|line| {
            line.map(|line| services::LogLine {
                time: line.time,
                text: line.text,
            })
            .map_err(|status| call_error("Logs", status))
        });
        Ok(Response::new(Box::pin(lines)))
    }
}

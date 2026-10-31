//! Serving behind authorization, with a fake serviced identifying every process as one service.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "a test: a failure is the test's"
)]
use std::os::unix::net::UnixListener;
use std::path::Path;

use libserviced::activation::ActivatedSocket;
use libserviced::api::ListServicesResponse;
use libserviced::api::LogLine;
use libserviced::api::LogsRequest;
use libserviced::api::ProcessRef;
use libserviced::api::ReloadResponse;
use libserviced::api::Service;
use libserviced::api::ServiceRef;
use libserviced::api::serviced_server::Serviced;
use libserviced::api::serviced_server::ServicedServer;
use libserviced::authorization::Caller;
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Server;

/// Both ends: serviced, and the service whose socket is protected.
enum Fake {
    /// serviced: every process belongs to this service, or to none.
    Serviced(Option<&'static str>),
    /// The protected service: `IdentifyProcess` answers with its caller.
    Protected,
}

#[tonic::async_trait]
impl Serviced for Fake {
    type LogsStream = tokio_stream::Empty<Result<LogLine, Status>>;

    async fn identify_process(
        &self,
        request: Request<ProcessRef>,
    ) -> Result<Response<ServiceRef>, Status> {
        let name = match self {
            Self::Serviced(Some(name)) => (*name).to_owned(),
            Self::Serviced(None) => return Err(Status::not_found("no service")),
            Self::Protected => Caller::of(&request)
                .ok_or_else(|| Status::failed_precondition("no caller"))?
                .service()
                .to_string(),
        };
        Ok(Response::new(ServiceRef { name }))
    }

    async fn list_services(
        &self,
        _: Request<()>,
    ) -> Result<Response<ListServicesResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn get_service(&self, _: Request<ServiceRef>) -> Result<Response<Service>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn start(&self, _: Request<ServiceRef>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn stop(&self, _: Request<ServiceRef>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn restart(&self, _: Request<ServiceRef>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn reload(&self, _: Request<()>) -> Result<Response<ReloadResponse>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn logs(&self, _: Request<LogsRequest>) -> Result<Response<Self::LogsStream>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn reboot(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented(""))
    }

    async fn power_off(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented(""))
    }
}

/// Serves the protected service on `dir/api.sock` to `allowed`, with a fake serviced on
/// `dir/serviced.sock` saying every caller is `identity`, and asks the protected service who
/// called it.
async fn call(dir: &Path, identity: Option<&'static str>, allowed: &str) -> Result<String, Status> {
    let serviced_path = dir.join("serviced.sock");
    let serviced_listener =
        tokio::net::UnixListener::bind(&serviced_path).expect("serviced's socket");
    let serviced = tokio::spawn(
        Server::builder()
            .add_service(ServicedServer::new(Fake::Serviced(identity)))
            .serve_with_incoming(UnixListenerStream::new(serviced_listener)),
    );

    let api_path = dir.join("api.sock");
    let socket = ActivatedSocket::new(
        "api".parse().expect("a socket name"),
        UnixListener::bind(&api_path).expect("the service's socket"),
        vec![allowed.parse().expect("a service name")],
    );
    let client = libserviced::connect_to(&serviced_path)
        .await
        .expect("connected to serviced");
    let (stop, stopped) = oneshot::channel::<()>();
    let protected = tokio::spawn(libserviced::authorization::serve(
        Server::builder().add_service(ServicedServer::new(Fake::Protected)),
        socket,
        client,
        async {
            let _ = stopped.await;
        },
    ));

    // A refused connection may fail when connecting or on the call.
    let result = match libserviced::connect_to(&api_path).await {
        Ok(mut api) => api
            .identify_process(ProcessRef { pid: 1 })
            .await
            .map(|response| response.into_inner().name),
        Err(error) => Err(Status::unavailable(error.to_string())),
    };

    stop.send(()).expect("the service is serving");
    protected
        .await
        .expect("the service's task")
        .expect("served until stopped");
    serviced.abort();
    result
}

#[tokio::test]
async fn an_allowed_caller_is_served_and_seen_by_handlers() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let caller = call(dir.path(), Some("hctl"), "hctl")
        .await
        .expect("an allowed call");
    assert_eq!(caller, "hctl");
}

#[tokio::test]
async fn a_caller_not_in_the_allow_list_is_refused() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let result = call(dir.path(), Some("intruder"), "hctl").await;
    assert!(result.is_err(), "{result:?}");
}

#[tokio::test]
async fn a_process_of_no_service_is_refused() {
    let dir = tempfile::tempdir().expect("a temporary directory");
    let result = call(dir.path(), None, "hctl").await;
    assert!(result.is_err(), "{result:?}");
}

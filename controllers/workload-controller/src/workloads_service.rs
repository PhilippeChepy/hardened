//! The API's `Workloads`: workloads are services of serviced (`workload-<name>`). User-data's are
//! in the runtime layer ([`crate::controller`]); the API's in the persistent layer, written here,
//! which serviced (re)starts once reloaded and keeps across reboots. `Exec` is relayed to
//! workload-console, which runs `ctr`: workload-controller only checks the request.

use std::path::PathBuf;

use controllers_helpers::WorkloadName;
use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::WithinResult as _;
use futures_util::StreamExt;
use futures_util::stream;
use futures_util::stream::BoxStream;
use libserviced::api;
use libserviced::api::exit::How;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::client;
use libserviced::definition;
use libserviced::definition::Layer;
use tokio::sync::MappedMutexGuard;
use tokio::sync::MutexGuard;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use tonic::transport::Channel;
use workload_console::ExecProcess;
use workload_console::console;
use workload_console::console::console_client::ConsoleClient;
use workload_controller::ImageWorkload;
use workload_controller::workloads;
use workload_controller::workloads::ApplyWorkloadRequest;
use workload_controller::workloads::ListWorkloadsResponse;
use workload_controller::workloads::LogChunk;
use workload_controller::workloads::WorkloadLogsRequest;
use workload_controller::workloads::WorkloadRef;
use workload_controller::workloads::WorkloadSource;
use workload_controller::workloads::workloads_server::Workloads;

use crate::configuration::Configuration;
use crate::controller;
use crate::controller::SharedConfiguration;
use crate::defined_workload::DefinedWorkload;
use crate::defined_workload::Source;
use crate::service_file;

/// Serves `Workloads` through serviced.
pub struct WorkloadsService {
    serviced: ServicedClient<Channel>,
    console: Channel,
    /// Below which serviced's layers are: `/` but in tests.
    root: PathBuf,
    configuration: SharedConfiguration,
}

impl WorkloadsService {
    /// Serves the workloads `serviced` runs, writing the API's in its persistent layer below
    /// `root`, refusing changes `configuration` forbids, running processes through `console`.
    #[must_use]
    pub fn new(
        serviced: ServicedClient<Channel>,
        console: Channel,
        root: PathBuf,
        configuration: SharedConfiguration,
    ) -> Self {
        Self {
            serviced,
            console,
            root,
            configuration,
        }
    }

    /// The configuration, which must be there to change the API's workloads: the names user-data
    /// owns.
    async fn configured(&self) -> Result<MappedMutexGuard<'_, Configuration>, Status> {
        MutexGuard::try_map(self.configuration.lock().await, Option::as_mut)
            .map_err(|_| Status::unavailable("workload-controller is not configured yet"))
    }

    /// Fails unless the workload `name` runs.
    async fn require_running(&self, name: &WorkloadName) -> Result<(), Status> {
        let request = api::ServiceRef {
            name: name.service_name().to_string(),
        };
        let service = match self.serviced.clone().get_service(request).await {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == Code::NotFound => return Err(not_found(name)),
            Err(status) => return Err(client::call_error("GetService", status)),
        };
        match service.state() {
            api::State::Running | api::State::Ready => Ok(()),
            _ => Err(Status::failed_precondition(format!(
                "workload {name} is not running"
            ))),
        }
    }
}

/// Refuses changes to workloads user-data declares: the API only manages its own. A disabled
/// user-data workload has no service, but still owns its name.
fn refuse_user_data(configuration: &Configuration, name: &WorkloadName) -> Result<(), Status> {
    if configuration.declares(name) {
        return Err(Status::failed_precondition(format!(
            "workload {name} is defined by user-data"
        )));
    }
    Ok(())
}

#[tonic::async_trait]
impl Workloads for WorkloadsService {
    async fn list(&self, _: Request<()>) -> Result<Response<ListWorkloadsResponse>, Status> {
        let services = self
            .serviced
            .clone()
            .list_services(())
            .await
            .map_err(|status| client::call_error("ListServices", status))?
            .into_inner()
            .services;
        let workloads = DefinedWorkload::from_services(services)
            .into_iter()
            .map(|(defined, service)| proto_workload(defined, Some(&service)))
            .collect();
        Ok(Response::new(ListWorkloadsResponse { workloads }))
    }

    async fn apply(
        &self,
        request: Request<ApplyWorkloadRequest>,
    ) -> Result<Response<workloads::Workload>, Status> {
        let ApplyWorkloadRequest { name, spec } = request.into_inner();
        let name = parse_name(name)?;
        let spec = spec.ok_or_else(|| Status::invalid_argument("spec: is required"))?;
        if spec.console {
            // A remote client must not flood the serial console.
            return Err(Status::invalid_argument(
                "spec.console: only user-data workloads copy their output to the console",
            ));
        }
        let workload = ImageWorkload::try_from(spec)
            .map_err(|error| Status::invalid_argument(format!("spec: {error}")))?;
        let configuration = self.configured().await?;
        refuse_user_data(&configuration, &name)?;

        let service = name.service_name().clone();
        let contents = service_file::to_toml(&name, &workload)
            .map_err(|error| Status::internal(format!("workload {name}: {error}")))?;
        definition::write_service_file(&self.root, Layer::Persistent, &service, &contents)
            .map_err(controller::service_file_error)?;
        client::reload(&mut self.serviced.clone()).await?;
        tracing::info!(workload = %name, "workload applied through the API");

        let defined = DefinedWorkload {
            name,
            workload,
            source: Source::Api,
        };
        // serviced starts it after its reload: its state then is not this call's.
        Ok(Response::new(proto_workload(defined, None)))
    }

    async fn remove(&self, request: Request<WorkloadRef>) -> Result<Response<()>, Status> {
        let name = parse_name(request.into_inner().name)?;
        // Held until serviced reloaded.
        let configuration = self.configured().await?;
        refuse_user_data(&configuration, &name)?;
        let service = name.service_name().clone();
        let removed = definition::remove_service_file(&self.root, Layer::Persistent, &service)
            .map_err(controller::service_file_error)?;
        if !removed {
            return Err(not_found(&name));
        }
        client::reload(&mut self.serviced.clone()).await?;
        tracing::info!(workload = %name, "workload removed through the API");
        Ok(Response::new(()))
    }

    async fn restart(&self, request: Request<WorkloadRef>) -> Result<Response<()>, Status> {
        let name = parse_name(request.into_inner().name)?;
        let request = api::ServiceRef {
            name: name.service_name().to_string(),
        };
        match self.serviced.clone().restart(request).await {
            Ok(_) => Ok(Response::new(())),
            Err(status) if status.code() == Code::NotFound => Err(not_found(&name)),
            Err(status) => Err(client::call_error("Restart", status)),
        }
    }

    type LogsStream = BoxStream<'static, Result<LogChunk, Status>>;

    async fn logs(
        &self,
        request: Request<WorkloadLogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let WorkloadLogsRequest { name, follow, tail } = request.into_inner();
        let name = parse_name(name)?;
        let request = api::LogsRequest {
            service: name.service_name().to_string(),
            tail,
            follow,
        };
        let lines = match self.serviced.clone().logs(request).await {
            Ok(response) => response.into_inner(),
            Err(status) if status.code() == Code::NotFound => return Err(not_found(&name)),
            Err(status) => return Err(client::call_error("Logs", status)),
        };
        let chunks = lines.map(|line| {
            line.map(|line| LogChunk {
                data: format!("{}\n", line.text).into_bytes(),
            })
            .map_err(|status| client::call_error("Logs", status))
        });
        Ok(Response::new(chunks.boxed()))
    }

    type ExecStream = BoxStream<'static, Result<console::ExecResponse, Status>>;

    async fn exec(
        &self,
        request: Request<Streaming<workloads::ExecRequest>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        use workloads::exec_request::Request as Wire;

        let mut requests = request.into_inner();
        let Some(workloads::ExecRequest {
            request: Some(Wire::Start(start)),
        }) = requests.message().await?
        else {
            return Err(Status::invalid_argument(
                "the first request must be the start",
            ));
        };
        let name = parse_name(start.name)?;
        let process = invalid_message::required(start.process, "process")
            .and_then(|process| ExecProcess::try_from(process).within("process"))
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        self.require_running(&name).await?;
        let workload = name.to_string();
        tracing::info!(workload = %name, "running a process in the workload");

        let start = console::ExecRequest {
            request: Some(console::exec_request::Request::Start(console::ExecStart {
                workload,
                process: Some(process.into()),
            })),
        };
        // Anything but an input ends the requests, which kills the process.
        let inputs = tokio_stream::StreamExt::map_while(requests, |request| match request {
            Ok(workloads::ExecRequest {
                request: Some(Wire::Input(input)),
            }) => Some(console::ExecRequest {
                request: Some(console::exec_request::Request::Input(input)),
            }),
            _ => None,
        });
        let responses = ConsoleClient::new(self.console.clone())
            .exec(stream::iter([start]).chain(inputs))
            .await?
            .into_inner();
        Ok(Response::new(responses.boxed()))
    }
}

#[must_use]
fn not_found(name: &WorkloadName) -> Status {
    Status::not_found(format!("no workload named {name}"))
}

fn parse_name(name: String) -> Result<WorkloadName, Status> {
    WorkloadName::try_from(name).map_err(|error| Status::invalid_argument(error.to_string()))
}

/// The API's view of a workload, and of its service's state if serviced has it.
#[must_use]
fn proto_workload(defined: DefinedWorkload, service: Option<&api::Service>) -> workloads::Workload {
    let source = match defined.source {
        Source::UserData => WorkloadSource::UserData,
        Source::Api => WorkloadSource::Api,
    };
    workloads::Workload {
        name: defined.name.into(),
        spec: Some(defined.workload.into()),
        source: source.into(),
        restarts: service.map_or(0, |service| service.restarts),
        state: Some(workload_state(service)),
    }
}

/// The API's view of a service's state; without a service, serviced has not loaded it yet.
#[must_use]
fn workload_state(service: Option<&api::Service>) -> workloads::workload::State {
    use api::State;
    use workloads::workload::Exited;
    use workloads::workload::Failed;
    use workloads::workload::Pending;
    use workloads::workload::Pulling;
    use workloads::workload::Running;
    use workloads::workload::State as Wire;

    let Some(service) = service else {
        return Wire::Pending(Pending {});
    };
    let last_exit = service.last_exit.and_then(|exit| exit.how);
    match service.state() {
        State::Unspecified
        | State::Waiting
        | State::Backoff
        | State::Inactive
        | State::Stopping
        | State::Stopped => Wire::Pending(Pending {}),
        // `exec-pre` pulls the image.
        State::Starting => Wire::Pulling(Pulling {}),
        // The wire format has no "unknown": 0 is never a container's pid.
        State::Running | State::Ready => Wire::Running(Running {
            pid: service.pid.unwrap_or(0),
        }),
        State::Exited => Wire::Exited(Exited {
            exit_code: match last_exit {
                Some(How::Code(code)) => code,
                // As shells report it.
                Some(How::Signal(signal)) => 128 + signal,
                None => 0,
            },
        }),
        State::Failed => Wire::Failed(Failed {
            reason: match (service.reason.as_str(), last_exit) {
                ("", Some(How::Code(code))) => format!("exit code {code}"),
                ("", Some(How::Signal(signal))) => format!("signal {signal}"),
                (reason, _) => reason.to_owned(),
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use libserviced::testing::Call;
    use libserviced::testing::FakeServiced;
    use tokio::net::UnixListener;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::transport::Server;
    use workload_console::console::console_server::Console;
    use workload_console::console::console_server::ConsoleServer;
    use workload_console::console::exec_input;
    use workload_console::console::exec_response;
    use workload_controller::workload;
    use workload_controller::workloads::workloads_client::WorkloadsClient;
    use workload_controller::workloads::workloads_server::WorkloadsServer;
    use workloads::workload::Exited;
    use workloads::workload::Failed;
    use workloads::workload::Pending;
    use workloads::workload::Pulling;
    use workloads::workload::Running;
    use workloads::workload::State as Wire;

    use super::*;
    use crate::service_file::tests::declared;
    use crate::service_file::tests::workload;

    fn service(state: api::State) -> api::Service {
        let mut service = api::Service::default();
        service.set_state(state);
        service
    }

    fn exit(how: How) -> Option<api::Exit> {
        Some(api::Exit { how: Some(how) })
    }

    #[test]
    fn service_states_map_to_workload_states() {
        assert_eq!(workload_state(None), Wire::Pending(Pending {}));
        assert_eq!(
            workload_state(Some(&service(api::State::Starting))),
            Wire::Pulling(Pulling {})
        );
        let running = api::Service {
            pid: Some(7),
            ..service(api::State::Ready)
        };
        assert_eq!(
            workload_state(Some(&running)),
            Wire::Running(Running { pid: 7 })
        );

        let killed = api::Service {
            last_exit: exit(How::Signal(9)),
            ..service(api::State::Exited)
        };
        assert_eq!(
            workload_state(Some(&killed)),
            Wire::Exited(Exited { exit_code: 137 })
        );

        let failed = api::Service {
            reason: "pulling the image failed".into(),
            last_exit: exit(How::Code(1)),
            ..service(api::State::Failed)
        };
        assert_eq!(
            workload_state(Some(&failed)),
            Wire::Failed(Failed {
                reason: "pulling the image failed".into()
            })
        );
        let crashed = api::Service {
            last_exit: exit(How::Signal(11)),
            ..service(api::State::Failed)
        };
        assert_eq!(
            workload_state(Some(&crashed)),
            Wire::Failed(Failed {
                reason: "signal 11".into()
            })
        );
    }

    struct Test {
        dir: tempfile::TempDir,
        fake: FakeServiced,
        service: WorkloadsService,
    }

    impl Test {
        /// With `configuration`, as machine-controller gave it, and a [`FakeConsole`].
        async fn new(configuration: Option<workload::Configuration>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (fake, client) = FakeServiced::start(dir.path(), dir.path()).await;
            let console = serve(
                &dir.path().join("console.sock"),
                ConsoleServer::new(FakeConsole),
            );
            let configuration = configuration.map(|message| message.try_into().unwrap());
            let service = WorkloadsService::new(
                client,
                console,
                dir.path().to_owned(),
                Arc::new(configuration.into()),
            );
            Self { dir, fake, service }
        }

        /// Serves the service, for the streaming calls, and connects to it.
        fn client(self) -> (tempfile::TempDir, FakeServiced, WorkloadsClient<Channel>) {
            let socket = self.dir.path().join("workloads.sock");
            let channel = serve(&socket, WorkloadsServer::new(self.service));
            (self.dir, self.fake, WorkloadsClient::new(channel))
        }
    }

    /// Serves `service` on `socket`, and a channel to it.
    fn serve<S>(socket: &std::path::Path, service: S) -> Channel
    where
        S: tower::Service<
                http::Request<tonic::body::Body>,
                Response = http::Response<tonic::body::Body>,
                Error = std::convert::Infallible,
            > + tonic::server::NamedService
            + Clone
            + Send
            + Sync
            + 'static,
        S::Future: Send + 'static,
    {
        let listener = UnixListener::bind(socket).unwrap();
        let server = Server::builder().add_service(service);
        tokio::spawn(server.serve_with_incoming(UnixListenerStream::new(listener)));
        controllers_helpers::lazy_channel(socket)
    }

    /// A workload-console printing the container and command it is asked to run, then echoing
    /// stdin until it is closed, then exiting with 7.
    struct FakeConsole;

    fn output(response: exec_response::Response) -> Result<console::ExecResponse, Status> {
        Ok(console::ExecResponse {
            response: Some(response),
        })
    }

    #[tonic::async_trait]
    impl Console for FakeConsole {
        type ExecStream = ReceiverStream<Result<console::ExecResponse, Status>>;

        async fn exec(
            &self,
            request: Request<Streaming<console::ExecRequest>>,
        ) -> Result<Response<Self::ExecStream>, Status> {
            use console::exec_request::Request as Wire;

            let mut requests = request.into_inner();
            let Some(Wire::Start(start)) = requests.message().await?.unwrap().request else {
                panic!("the first request is the start");
            };
            let started = format!("{} {:?}\n", start.workload, start.process.unwrap().command);
            let (responses, stream) = mpsc::channel(4);
            tokio::spawn(async move {
                let stdout = exec_response::Response::Stdout;
                responses
                    .send(output(stdout(started.into())))
                    .await
                    .unwrap();
                while let Some(request) = requests.message().await.unwrap() {
                    let Some(Wire::Input(input)) = request.request else {
                        panic!("the next requests are inputs");
                    };
                    match input.input.unwrap() {
                        exec_input::Input::Stdin(data) => {
                            responses.send(output(stdout(data))).await.unwrap();
                        }
                        exec_input::Input::CloseStdin(()) => break,
                        exec_input::Input::Resize(_) => {}
                    }
                }
                let exit = exec_response::Response::ExitCode(7);
                responses.send(output(exit)).await.unwrap();
            });
            Ok(Response::new(ReceiverStream::new(stream)))
        }
    }

    /// User-data declaring the workloads `names` (disabled).
    fn user_data(names: &[&str]) -> Option<workload::Configuration> {
        let workloads = names.iter().map(|name| declared(name, false)).collect();
        Some(workload::Configuration { workloads })
    }

    /// The fixture's workload, as the API may declare it: without the console.
    fn api_workload() -> ImageWorkload {
        let spec = workloads::WorkloadSpec {
            console: false,
            ..workload().into()
        };
        ImageWorkload::try_from(spec).unwrap()
    }

    fn apply(name: &str) -> Request<ApplyWorkloadRequest> {
        Request::new(ApplyWorkloadRequest {
            name: name.into(),
            spec: Some(api_workload().into()),
        })
    }

    fn workload_ref(name: &str) -> Request<WorkloadRef> {
        Request::new(WorkloadRef { name: name.into() })
    }

    #[tokio::test]
    async fn applies_lists_and_removes_the_apis_workloads() {
        let test = Test::new(user_data(&["web"])).await;
        let applied = test.service.apply(apply("db")).await.unwrap().into_inner();
        assert_eq!(applied.source, i32::from(WorkloadSource::Api));
        assert_eq!(applied.state, Some(Wire::Pending(Pending {})));
        assert_eq!(test.fake.take_calls(), [Call::Reload]);
        assert!(test.fake.file(Layer::Persistent, "workload-db").is_some());

        let listed = test.service.list(Request::new(())).await.unwrap();
        let listed = listed.into_inner().workloads;
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "db");
        assert_eq!(listed[0].spec, Some(api_workload().into()));

        test.service.restart(workload_ref("db")).await.unwrap();
        test.service.remove(workload_ref("db")).await.unwrap();
        assert_eq!(
            test.fake.take_calls(),
            [Call::Restart("workload-db".into()), Call::Reload]
        );
        let status = test.service.remove(workload_ref("db")).await.unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
        let status = test.service.restart(workload_ref("db")).await.unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }

    fn exec_start(name: &str, command: &[&str]) -> workloads::ExecRequest {
        let process = console::Process {
            command: command.iter().map(|&argument| argument.into()).collect(),
            terminal: None,
        };
        workloads::ExecRequest {
            request: Some(workloads::exec_request::Request::Start(
                workloads::ExecStart {
                    name: name.into(),
                    process: Some(process),
                },
            )),
        }
    }

    fn exec_input(input: exec_input::Input) -> workloads::ExecRequest {
        workloads::ExecRequest {
            request: Some(workloads::exec_request::Request::Input(
                console::ExecInput { input: Some(input) },
            )),
        }
    }

    #[tokio::test]
    async fn relays_exec_to_the_console_of_running_workloads() {
        let test = Test::new(user_data(&[])).await;
        test.service.apply(apply("db")).await.unwrap();
        test.fake.set_state("workload-db", api::State::Running);
        let (_dir, _fake, mut client) = test.client();

        let requests = [
            exec_start("db", &["cat"]),
            exec_input(exec_input::Input::Stdin(b"hello".to_vec())),
            exec_input(exec_input::Input::CloseStdin(())),
        ];
        let mut responses = client
            .exec(stream::iter(requests))
            .await
            .unwrap()
            .into_inner();
        let mut received = Vec::new();
        while let Some(response) = responses.message().await.unwrap() {
            received.push(response.response.unwrap());
        }
        assert_eq!(
            received,
            [
                exec_response::Response::Stdout(b"db [\"cat\"]\n".to_vec()),
                exec_response::Response::Stdout(b"hello".to_vec()),
                exec_response::Response::ExitCode(7),
            ]
        );
    }

    #[tokio::test]
    async fn refuses_exec_in_what_does_not_run() {
        let test = Test::new(user_data(&[])).await;
        test.service.apply(apply("db")).await.unwrap();
        test.fake.set_state("workload-db", api::State::Backoff);
        let (_dir, _fake, mut client) = test.client();

        let exec = async |request| {
            client
                .clone()
                .exec(stream::iter([request]))
                .await
                .unwrap_err()
                .code()
        };
        assert_eq!(
            exec(exec_start("db", &["sh"])).await,
            Code::FailedPrecondition
        );
        assert_eq!(exec(exec_start("web", &["sh"])).await, Code::NotFound);
        assert_eq!(exec(exec_start("db", &[])).await, Code::InvalidArgument);
        let input = exec_input(exec_input::Input::CloseStdin(()));
        assert_eq!(exec(input).await, Code::InvalidArgument);
        assert_eq!(
            client.list(()).await.unwrap().into_inner().workloads.len(),
            1
        );
    }

    #[tokio::test]
    async fn refuses_what_the_configuration_forbids() {
        let unconfigured = Test::new(None).await;
        let status = unconfigured.service.apply(apply("db")).await.unwrap_err();
        assert_eq!(status.code(), Code::Unavailable);

        let test = Test::new(user_data(&["web"])).await;
        let status = test.service.apply(apply("web")).await.unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition);
        let status = test.service.remove(workload_ref("web")).await.unwrap_err();
        assert_eq!(status.code(), Code::FailedPrecondition);
        assert_eq!(test.fake.take_calls(), []);
    }

    #[tokio::test]
    async fn rejects_invalid_requests_like_user_data() {
        let test = Test::new(user_data(&[])).await;
        let status = test.service.apply(apply("Web")).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        let mut spec = workloads::WorkloadSpec::from(api_workload());
        spec.command[0] = "a\0b".into();
        let request = Request::new(ApplyWorkloadRequest {
            name: "db".into(),
            spec: Some(spec),
        });
        let status = test.service.apply(request).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        let mut spec = workloads::WorkloadSpec::from(workload());
        spec.console = true;
        let request = Request::new(ApplyWorkloadRequest {
            name: "db".into(),
            spec: Some(spec),
        });
        let status = test.service.apply(request).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        let request = Request::new(ApplyWorkloadRequest {
            name: "db".into(),
            spec: None,
        });
        let status = test.service.apply(request).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert_eq!(test.fake.take_calls(), []);
    }
}

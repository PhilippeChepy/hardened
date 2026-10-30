//! The API's `Workloads`: workloads are services of serviced (`workload-<name>`). User-data's are
//! in the runtime layer ([`crate::controller`]); the API's in the persistent layer, written here,
//! which serviced (re)starts once reloaded and keeps across reboots.

use std::path::PathBuf;

use controllers_helpers::WorkloadName;
use futures_util::StreamExt;
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
use tonic::transport::Channel;
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
    /// Below which serviced's layers are: `/` but in tests.
    root: PathBuf,
    configuration: SharedConfiguration,
}

impl WorkloadsService {
    /// Serves the workloads `serviced` runs, writing the API's in its persistent layer below
    /// `root`, refusing changes `configuration` forbids.
    #[must_use]
    pub fn new(
        serviced: ServicedClient<Channel>,
        root: PathBuf,
        configuration: SharedConfiguration,
    ) -> Self {
        Self {
            serviced,
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

        let service = service_file::service_name(&name);
        let contents = service_file::to_toml(&name, &workload);
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
        let service = service_file::service_name(&name);
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
            name: service_file::service_name(&name).to_string(),
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
            service: service_file::service_name(&name).to_string(),
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
    use workload_controller::workload;
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
        _dir: tempfile::TempDir,
        fake: FakeServiced,
        service: WorkloadsService,
    }

    impl Test {
        /// With `configuration`, as machine-controller gave it.
        async fn new(configuration: Option<workload::Configuration>) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (fake, client) = FakeServiced::start(dir.path(), dir.path()).await;
            let configuration = configuration.map(|message| message.try_into().unwrap());
            let service = WorkloadsService::new(
                client,
                dir.path().to_owned(),
                Arc::new(configuration.into()),
            );
            Self {
                _dir: dir,
                fake,
                service,
            }
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

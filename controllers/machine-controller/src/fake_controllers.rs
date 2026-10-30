//! Fakes of the APIs machine-controller calls, on unix sockets in a temporary directory, which
//! record the calls the tests check.

use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use controllers_helpers::base64_text;
use controllers_helpers::testing;
use kubelet_controller::kubelet;
use kubelet_controller::kubelet::kubelet_controller_server::KubeletController;
use kubelet_controller::kubelet::kubelet_controller_server::KubeletControllerServer;
use libserviced::api;
use libserviced::api::serviced_server::Serviced;
use libserviced::api::serviced_server::ServicedServer;
use libserviced::definition::Layer;
use machine_apiproxy::apiproxy;
use machine_apiproxy::apiproxy::machine_api_proxy_server::MachineApiProxy;
use machine_apiproxy::apiproxy::machine_api_proxy_server::MachineApiProxyServer;
use network_controller::network;
use network_controller::network::network_controller_server::NetworkController;
use network_controller::network::network_controller_server::NetworkControllerServer;
use storage_controller::storage;
use storage_controller::storage::storage_controller_server::StorageController;
use storage_controller::storage::storage_controller_server::StorageControllerServer;
use tempfile::TempDir;
use time_controller::time;
use time_controller::time::time_controller_server::TimeController;
use time_controller::time::time_controller_server::TimeControllerServer;
use tokio::net::UnixListener;
use tokio_stream::Stream;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Server;
use tonic::transport::server::Router;
use trust_controller::attestation;
use trust_controller::attestation::attestation_server::Attestation;
use trust_controller::attestation::attestation_server::AttestationServer;
use workload_controller::workload;
use workload_controller::workload::workload_controller_server::WorkloadController;
use workload_controller::workload::workload_controller_server::WorkloadControllerServer;
use workload_controller::workloads;
use workload_controller::workloads::workloads_server::Workloads;
use workload_controller::workloads::workloads_server::WorkloadsServer;

use crate::controllers::Controllers;

/// A stream of a fake's answers.
type Answers<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// The calls the fakes received, in order.
type Calls = Arc<Mutex<Vec<String>>>;

/// User-data enabling the API, with a self-signed certificate.
pub fn api_user_data() -> String {
    let (certificate, key) = testing::certificate_and_key();
    let certificate = base64_text::encode(certificate);
    format!(
        "[settings.hardened.api]\nclient-ca = \"{certificate}\"\n\
         certificate = \"{certificate}\"\nprivate-key = \"{}\"\n",
        base64_text::encode(key)
    )
}

/// The fakes, and the [`Controllers`] calling them.
pub struct FakeControllers {
    pub controllers: Arc<Controllers>,
    calls: Calls,
    dir: TempDir,
}

impl FakeControllers {
    /// Serves every fake but trust-controller's (no TPM): a Kubernetes target's.
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let fakes = Self {
            controllers: Arc::new(Controllers::in_dir(dir.path())),
            calls: Calls::default(),
            dir,
        };
        fs::create_dir_all(Layer::Runtime.dir_in(fakes.dir.path())).unwrap();
        let fake = Fake(fakes.calls.clone());
        let services = [
            (
                "network-controller",
                Server::builder().add_service(NetworkControllerServer::new(fake.clone())),
            ),
            (
                "storage-controller",
                Server::builder().add_service(StorageControllerServer::new(fake.clone())),
            ),
            (
                "time-controller",
                Server::builder().add_service(TimeControllerServer::new(fake.clone())),
            ),
            (
                "workload-controller",
                Server::builder()
                    .add_service(WorkloadControllerServer::new(fake.clone()))
                    .add_service(WorkloadsServer::new(fake.clone())),
            ),
            (
                "machine-apiproxy",
                Server::builder().add_service(MachineApiProxyServer::new(fake.clone())),
            ),
            (
                "kubelet-controller",
                Server::builder().add_service(KubeletControllerServer::new(fake.clone())),
            ),
            (
                "serviced",
                Server::builder().add_service(ServicedServer::new(fake)),
            ),
        ];
        for (name, router) in services {
            fakes.serve(name, router);
        }
        fakes
    }

    /// Serves trust-controller's fake, as on a machine with a TPM.
    pub fn start_trust(&self) {
        self.serve(
            "trust-controller",
            Server::builder().add_service(AttestationServer::new(Fake(self.calls.clone()))),
        );
    }

    fn serve(&self, name: &str, router: Router) {
        let listener = UnixListener::bind(self.socket(name)).unwrap();
        tokio::spawn(router.serve_with_incoming(UnixListenerStream::new(listener)));
    }

    /// Makes `name` unreachable, as if it did not exist.
    pub fn stop(&self, name: &str) {
        fs::remove_file(self.socket(name)).unwrap();
    }

    /// The root of serviced's layers.
    pub fn dir(&self) -> &Path {
        self.dir.path()
    }

    fn socket(&self, name: &str) -> PathBuf {
        self.dir.path().join(format!("{name}.sock"))
    }

    /// The calls since the last time.
    pub fn calls(&self) -> Vec<String> {
        std::mem::take(&mut self.calls.lock().unwrap())
    }
}

/// Every fake, recording its calls.
#[derive(Clone)]
struct Fake(Calls);

impl Fake {
    fn record(&self, call: String) {
        self.0.lock().unwrap().push(call);
    }
}

#[tonic::async_trait]
impl NetworkController for Fake {
    async fn configure(
        &self,
        request: Request<network::Configuration>,
    ) -> Result<Response<()>, Status> {
        let name_servers = request.into_inner().name_servers;
        self.record(format!(
            "network-controller Configure name_servers={name_servers:?}"
        ));
        Ok(Response::new(()))
    }

    async fn get_state(&self, _: Request<()>) -> Result<Response<network::State>, Status> {
        Err(Status::unimplemented("fake"))
    }
}

#[tonic::async_trait]
impl StorageController for Fake {
    async fn configure(
        &self,
        request: Request<storage::Configuration>,
    ) -> Result<Response<()>, Status> {
        let encryption = request.into_inner().encryption();
        self.record(format!(
            "storage-controller Configure encryption={encryption:?}"
        ));
        Ok(Response::new(()))
    }

    async fn get_state(&self, _: Request<()>) -> Result<Response<storage::State>, Status> {
        Ok(Response::new(storage::State {
            size_bytes: 1 << 30,
            ..storage::State::default()
        }))
    }
}

#[tonic::async_trait]
impl TimeController for Fake {
    async fn configure(
        &self,
        request: Request<time::Configuration>,
    ) -> Result<Response<()>, Status> {
        let configuration = request.into_inner();
        self.record(format!(
            "time-controller Configure servers={:?} origin={:?}",
            configuration.servers,
            configuration.origin()
        ));
        Ok(Response::new(()))
    }

    async fn get_status(&self, _: Request<()>) -> Result<Response<time::Status>, Status> {
        Ok(Response::new(time::Status {
            clock: Some(time::Clock {
                synchronized: true,
                ..time::Clock::default()
            }),
            ..time::Status::default()
        }))
    }
}

#[tonic::async_trait]
impl WorkloadController for Fake {
    async fn configure(
        &self,
        request: Request<workload::Configuration>,
    ) -> Result<Response<()>, Status> {
        let workloads = request.into_inner().workloads;
        let names: Vec<String> = workloads.into_iter().map(|w| w.name).collect();
        self.record(format!("workload-controller Configure workloads={names:?}"));
        Ok(Response::new(()))
    }
}

#[tonic::async_trait]
impl Workloads for Fake {
    async fn list(
        &self,
        _: Request<()>,
    ) -> Result<Response<workloads::ListWorkloadsResponse>, Status> {
        Ok(Response::new(workloads::ListWorkloadsResponse {
            workloads: vec![workloads::Workload {
                name: "web".to_owned(),
                ..workloads::Workload::default()
            }],
        }))
    }

    async fn apply(
        &self,
        request: Request<workloads::ApplyWorkloadRequest>,
    ) -> Result<Response<workloads::Workload>, Status> {
        let name = request.into_inner().name;
        self.record(format!("workload-controller Apply {name}"));
        Ok(Response::new(workloads::Workload {
            name,
            ..workloads::Workload::default()
        }))
    }

    async fn remove(
        &self,
        request: Request<workloads::WorkloadRef>,
    ) -> Result<Response<()>, Status> {
        Err(Status::not_found(format!(
            "no workload {}",
            request.into_inner().name
        )))
    }

    async fn restart(&self, _: Request<workloads::WorkloadRef>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("fake"))
    }

    type LogsStream = Answers<workloads::LogChunk>;

    async fn logs(
        &self,
        _: Request<workloads::WorkloadLogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let chunks = ["first\n", "second\n"].map(|text| {
            Ok(workloads::LogChunk {
                data: text.as_bytes().to_vec(),
            })
        });
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks))))
    }

    type ExecStream = Answers<workload_console::console::ExecResponse>;

    async fn exec(
        &self,
        _: Request<tonic::Streaming<workloads::ExecRequest>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        Err(Status::unimplemented("fake"))
    }
}

#[tonic::async_trait]
impl KubeletController for Fake {
    async fn configure(
        &self,
        request: Request<kubelet::Configuration>,
    ) -> Result<Response<()>, Status> {
        let configuration = request.into_inner();
        self.record(format!(
            "kubelet-controller Configure kubelet={} node_name={}",
            configuration.kubelet.is_some(),
            configuration.node_name
        ));
        Ok(Response::new(()))
    }
}

#[tonic::async_trait]
impl MachineApiProxy for Fake {
    async fn configure(
        &self,
        request: Request<apiproxy::Configuration>,
    ) -> Result<Response<()>, Status> {
        self.record(format!(
            "machine-apiproxy Configure listen={}",
            request.into_inner().listen
        ));
        Ok(Response::new(()))
    }
}

#[tonic::async_trait]
impl Attestation for Fake {
    async fn pcrs(
        &self,
        _: Request<attestation::PcrsRequest>,
    ) -> Result<Response<attestation::PcrsResponse>, Status> {
        Ok(Response::new(attestation::PcrsResponse {
            values: vec![attestation::PcrValue {
                index: 7,
                ..attestation::PcrValue::default()
            }],
            ..attestation::PcrsResponse::default()
        }))
    }

    async fn event_log(
        &self,
        _: Request<()>,
    ) -> Result<Response<attestation::EventLogResponse>, Status> {
        Err(Status::failed_precondition("no event log"))
    }

    async fn quote(
        &self,
        _: Request<attestation::QuoteRequest>,
    ) -> Result<Response<attestation::QuoteResponse>, Status> {
        Err(Status::unimplemented("fake"))
    }
}

/// The one service the fake serviced has, ready, its last run killed by SIGKILL.
fn containerd() -> api::Service {
    let mut service = api::Service {
        name: "containerd".to_owned(),
        description: "the container runtime".to_owned(),
        enabled: true,
        definition: "description = \"the container runtime\"\n\
                     exec = [\"/usr/bin/containerd\"]\n\
                     requires = [\"storage-controller\"]\n"
            .to_owned(),
        pid: Some(42),
        last_exit: Some(api::Exit {
            how: Some(api::exit::How::Signal(9)),
        }),
        ..api::Service::default()
    };
    service.set_state(api::State::Ready);
    service
}

#[tonic::async_trait]
impl Serviced for Fake {
    async fn list_services(
        &self,
        _: Request<()>,
    ) -> Result<Response<api::ListServicesResponse>, Status> {
        Ok(Response::new(api::ListServicesResponse {
            services: vec![containerd()],
        }))
    }

    async fn get_service(
        &self,
        request: Request<api::ServiceRef>,
    ) -> Result<Response<api::Service>, Status> {
        match request.into_inner().name.as_str() {
            "containerd" => Ok(Response::new(containerd())),
            name => Err(Status::not_found(format!("no service {name}"))),
        }
    }

    async fn start(&self, request: Request<api::ServiceRef>) -> Result<Response<()>, Status> {
        self.record(format!("serviced Start {}", request.into_inner().name));
        Ok(Response::new(()))
    }

    async fn stop(&self, request: Request<api::ServiceRef>) -> Result<Response<()>, Status> {
        self.record(format!("serviced Stop {}", request.into_inner().name));
        Ok(Response::new(()))
    }

    async fn restart(&self, request: Request<api::ServiceRef>) -> Result<Response<()>, Status> {
        self.record(format!("serviced Restart {}", request.into_inner().name));
        Ok(Response::new(()))
    }

    async fn reload(&self, _: Request<()>) -> Result<Response<api::ReloadResponse>, Status> {
        self.record("serviced Reload".to_owned());
        Ok(Response::new(api::ReloadResponse::default()))
    }

    type LogsStream = Answers<api::LogLine>;

    async fn logs(
        &self,
        request: Request<api::LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let request = request.into_inner();
        self.record(format!(
            "serviced Logs service={:?} tail={} follow={}",
            request.service, request.tail, request.follow
        ));
        let line = api::LogLine {
            target: "serviced".to_owned(),
            text: "boot complete".to_owned(),
            ..api::LogLine::default()
        };
        Ok(Response::new(Box::pin(tokio_stream::iter([Ok(line)]))))
    }

    async fn reboot(&self, _: Request<()>) -> Result<Response<()>, Status> {
        self.record("serviced Reboot".to_owned());
        Ok(Response::new(()))
    }

    async fn power_off(&self, _: Request<()>) -> Result<Response<()>, Status> {
        self.record("serviced PowerOff".to_owned());
        Ok(Response::new(()))
    }

    async fn identify_process(
        &self,
        _: Request<api::ProcessRef>,
    ) -> Result<Response<api::ServiceRef>, Status> {
        Err(Status::unimplemented("fake"))
    }
}

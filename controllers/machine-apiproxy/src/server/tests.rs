//! End to end: mTLS client -> machine-apiproxy -> a fake machine-controller on a unix socket in a
//! temporary directory.

use std::fs;
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;

use machine_apiproxy::ApiConfig;
use machine_apiproxy::Role;
use machine_apiproxy::apiproxy;
use machine_apiproxy::apiproxy::machine_api_proxy_server::MachineApiProxy;
use rcgen::BasicConstraints;
use rcgen::CertificateParams;
use rcgen::DnType;
use rcgen::ExtendedKeyUsagePurpose;
use rcgen::IsCa;
use rcgen::Issuer;
use rcgen::KeyPair;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::net::UnixListener;
use tokio::sync::oneshot;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Certificate;
use tonic::transport::Channel;
use tonic::transport::ClientTlsConfig;
use tonic::transport::Identity;
use workload_controller::workloads;
use workload_controller::workloads::workloads_client::WorkloadsClient;
use workload_controller::workloads::workloads_server::Workloads;
use workload_controller::workloads::workloads_server::WorkloadsServer;

use crate::api_listener::ApiListener;
use crate::configuration_service::ConfigurationService;
use crate::server;
use crate::state;
use crate::tls;

type Answers<T> = Pin<Box<dyn Stream<Item = Result<T, Status>> + Send>>;

/// A service of machine-controller's API (any one: they are forwarded alike), recording the
/// calls changing something.
#[derive(Clone, Default)]
struct FakeMachineController {
    calls: Arc<Mutex<Vec<String>>>,
}

impl FakeMachineController {
    fn record(&self, call: &str) {
        self.calls.lock().unwrap().push(call.to_owned());
    }
}

#[tonic::async_trait]
impl Workloads for FakeMachineController {
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
        self.record("Apply");
        Ok(Response::new(workloads::Workload {
            name: request.into_inner().name,
            ..workloads::Workload::default()
        }))
    }

    async fn remove(&self, _: Request<workloads::WorkloadRef>) -> Result<Response<()>, Status> {
        Err(Status::not_found("no such workload"))
    }

    async fn restart(&self, _: Request<workloads::WorkloadRef>) -> Result<Response<()>, Status> {
        self.record("Restart");
        Ok(Response::new(()))
    }

    type LogsStream = Answers<workloads::LogChunk>;

    async fn logs(
        &self,
        request: Request<workloads::WorkloadLogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        if request.into_inner().name != "web" {
            return Err(Status::not_found("no such workload"));
        }
        let chunks = ["started\n", "serving\n"].map(|text| {
            Ok(workloads::LogChunk {
                data: text.as_bytes().to_vec(),
            })
        });
        Ok(Response::new(Box::pin(tokio_stream::iter(chunks))))
    }
}

struct Ca {
    pem: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    fn new(name: &str) -> Self {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let key = KeyPair::generate().unwrap();
        let pem = params.self_signed(&key).unwrap().pem();
        Self {
            pem,
            issuer: Issuer::new(params, key),
        }
    }

    /// A certificate and its private key, PEM-encoded.
    fn issue(
        &self,
        subject_alt_names: &[&str],
        common_name: &str,
        organization: Option<&str>,
        usage: ExtendedKeyUsagePurpose,
    ) -> (String, String) {
        let subject_alt_names: Vec<String> = subject_alt_names
            .iter()
            .map(|&name| name.to_owned())
            .collect();
        let mut params = CertificateParams::new(subject_alt_names).unwrap();
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        if let Some(organization) = organization {
            params
                .distinguished_name
                .push(DnType::OrganizationName, organization);
        }
        params.extended_key_usages = vec![usage];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    /// machine-apiproxy's configuration on `listen`, with a server certificate of this CA.
    fn api_config(&self, listen: SocketAddr) -> ApiConfig {
        let (certificate, private_key) = self.issue(
            &["localhost"],
            "machine-apiproxy",
            None,
            ExtendedKeyUsagePurpose::ServerAuth,
        );
        ApiConfig::try_from(apiproxy::Configuration {
            listen: listen.to_string(),
            tls: Some(apiproxy::TlsIdentity {
                client_ca: self.pem.clone(),
                certificate,
                private_key,
            }),
        })
        .unwrap()
    }
}

struct Harness {
    addr: SocketAddr,
    ca: Ca,
    upstream: FakeMachineController,
    dir: tempfile::TempDir,
    _stop: oneshot::Sender<()>,
}

/// Serves a fake machine-controller on `socket`.
fn serve_upstream(socket: &Path) -> FakeMachineController {
    let upstream = FakeMachineController::default();
    let listener = UnixListenerStream::new(UnixListener::bind(socket).unwrap());
    tokio::spawn(
        tonic::transport::Server::builder()
            .add_service(WorkloadsServer::new(upstream.clone()))
            .serve_with_incoming(listener),
    );
    upstream
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("machine-controller.sock");
        let upstream = serve_upstream(&socket);
        let ca = Ca::new("test CA");
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let tls = tls::server_config(&ca.api_config(addr)).unwrap();
        let (stop, stopped) = oneshot::channel();
        tokio::spawn(async move {
            let stopped = async {
                let _ = stopped.await;
            };
            server::serve(listener, Arc::new(tls), &socket, stopped).await;
        });
        Self {
            addr,
            ca,
            upstream,
            dir,
            _stop: stop,
        }
    }

    async fn channel(&self, role_org: Option<&str>) -> Channel {
        connect(&self.ca, self.addr, role_org).await.unwrap()
    }

    /// The calls to machine-controller that changed something.
    fn calls(&self) -> Vec<String> {
        std::mem::take(&mut self.upstream.calls.lock().unwrap())
    }
}

/// An mTLS channel to `addr`, with a client certificate of `ca` for `role_org`.
async fn connect(
    ca: &Ca,
    addr: SocketAddr,
    role_org: Option<&str>,
) -> Result<Channel, tonic::transport::Error> {
    let (cert, key) = ca.issue(&[], "alice", role_org, ExtendedKeyUsagePurpose::ClientAuth);
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(&ca.pem))
        .identity(Identity::from_pem(cert, key));
    Channel::from_shared(format!("https://{addr}"))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await
}

#[tokio::test]
async fn reader_reads_the_machine_but_cannot_change_it() {
    let harness = Harness::start().await;
    let mut workloads =
        WorkloadsClient::new(harness.channel(Some(Role::Reader.organization())).await);

    let list = workloads.list(()).await.unwrap().into_inner();
    assert_eq!(list.workloads[0].name, "web");
    let request = workloads::WorkloadLogsRequest {
        name: "web".to_owned(),
        ..workloads::WorkloadLogsRequest::default()
    };
    let chunks: Vec<Vec<u8>> = workloads
        .logs(request)
        .await
        .unwrap()
        .into_inner()
        .map(|chunk| chunk.unwrap().data)
        .collect()
        .await;
    assert_eq!(chunks, [b"started\n".to_vec(), b"serving\n".to_vec()]);
    let missing = workloads
        .logs(workloads::WorkloadLogsRequest::default())
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::NotFound, "statuses pass through");
    assert_eq!(missing.message(), "no such workload");

    let denied = workloads
        .apply(workloads::ApplyWorkloadRequest::default())
        .await
        .unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied, "{denied:?}");
    assert_eq!(denied.message(), "method requires the admin role");
    assert!(
        harness.calls().is_empty(),
        "nothing reached machine-controller"
    );
}

#[tokio::test]
async fn admin_changes_the_machine() {
    let harness = Harness::start().await;
    let mut workloads =
        WorkloadsClient::new(harness.channel(Some(Role::Admin.organization())).await);
    let applied = workloads
        .apply(workloads::ApplyWorkloadRequest {
            name: "web".to_owned(),
            spec: None,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(applied.name, "web");
    let missing = workloads
        .remove(workloads::WorkloadRef {
            name: "db".to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(missing.code(), Code::NotFound);
    workloads
        .restart(workloads::WorkloadRef {
            name: "web".to_owned(),
        })
        .await
        .unwrap();
    assert_eq!(harness.calls(), ["Apply", "Restart"]);
}

#[tokio::test]
async fn unreachable_machine_controller_is_unavailable() {
    let harness = Harness::start().await;
    fs::remove_file(harness.dir.path().join("machine-controller.sock")).unwrap();
    let channel = harness.channel(Some(Role::Reader.organization())).await;
    let error = WorkloadsClient::new(channel).list(()).await.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable, "{error:?}");
}

#[tokio::test]
async fn client_without_role_is_unauthenticated() {
    let harness = Harness::start().await;
    let channel = harness.channel(Some("hardened:root")).await;
    let error = WorkloadsClient::new(channel).list(()).await.unwrap_err();
    assert_eq!(error.code(), Code::Unauthenticated, "{error:?}");
}

#[tokio::test]
async fn unknown_ca_fails_the_handshake() {
    let harness = Harness::start().await;
    let stranger = Ca::new("another CA");
    let (cert, key) = stranger.issue(
        &[],
        "mallory",
        Some(Role::Admin.organization()),
        ExtendedKeyUsagePurpose::ClientAuth,
    );
    let tls = ClientTlsConfig::new()
        .domain_name("localhost")
        .ca_certificate(Certificate::from_pem(&harness.ca.pem))
        .identity(Identity::from_pem(cert, key));
    let channel = Channel::from_shared(format!("https://{}", harness.addr))
        .unwrap()
        .tls_config(tls)
        .unwrap()
        .connect()
        .await;
    match channel {
        Err(_) => {}
        // The server may abort the handshake after the client considers it done.
        Ok(channel) => assert!(WorkloadsClient::new(channel).list(()).await.is_err()),
    }
    assert!(
        TcpStream::connect(harness.addr).await.is_ok(),
        "still serving"
    );
}

/// A free local address: bound, then released.
async fn free_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
}

#[tokio::test]
async fn configuration_is_kept_and_served() {
    let dir = tempfile::tempdir().unwrap();
    let socket = dir.path().join("machine-controller.sock");
    serve_upstream(&socket);
    let state = dir.path().join("state.json");
    let listener = Arc::new(ApiListener::new(socket));
    let service = ConfigurationService::new(listener.clone(), state.clone());

    let ca = Ca::new("test CA");
    let addr = free_address().await;
    let config = ca.api_config(addr);
    service
        .configure(Request::new(config.clone().into()))
        .await
        .unwrap();
    let mode = fs::metadata(&state).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o600, "it holds the private key");
    assert_eq!(state::load(&state).unwrap(), Some(config.clone()));
    let channel = connect(&ca, addr, Some(Role::Reader.organization()))
        .await
        .unwrap();
    WorkloadsClient::new(channel).list(()).await.unwrap();

    // The same configuration again changes nothing; another replaces the listener.
    service
        .configure(Request::new(config.into()))
        .await
        .unwrap();
    let other = Ca::new("other CA");
    let moved = free_address().await;
    service
        .configure(Request::new(other.api_config(moved).into()))
        .await
        .unwrap();
    assert!(
        connect(&ca, addr, Some(Role::Reader.organization()))
            .await
            .is_err()
    );
    let channel = connect(&other, moved, Some(Role::Reader.organization()))
        .await
        .unwrap();
    WorkloadsClient::new(channel).list(()).await.unwrap();

    let invalid = apiproxy::Configuration {
        listen: "nowhere".to_owned(),
        tls: None,
    };
    let error = service.configure(Request::new(invalid)).await.unwrap_err();
    assert_eq!(error.code(), Code::InvalidArgument);
    listener.stop().await;
}

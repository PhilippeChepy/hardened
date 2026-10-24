//! End-to-end: mTLS client -> dust-api -> fake dust-init on a unix socket.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use dust_proto::Role;
use dust_proto::v1::machine_client::MachineClient;
use dust_proto::v1::machine_server::{Machine, MachineServer};
use dust_proto::v1::{LogEntry, LogsRequest, SettingsResponse, VersionResponse};
use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::oneshot;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};
use tonic::{Code, Request, Response, Status};

struct FakeDust;

#[tonic::async_trait]
impl Machine for FakeDust {
    async fn version(&self, _: Request<()>) -> Result<Response<VersionResponse>, Status> {
        Ok(Response::new(VersionResponse {
            os_name: "hardened".into(),
            ..Default::default()
        }))
    }

    type LogsStream = tokio_stream::Empty<Result<LogEntry, Status>>;

    async fn logs(&self, _: Request<LogsRequest>) -> Result<Response<Self::LogsStream>, Status> {
        Ok(Response::new(tokio_stream::empty()))
    }

    async fn get_settings(&self, _: Request<()>) -> Result<Response<SettingsResponse>, Status> {
        Err(Status::unimplemented("fake"))
    }

    async fn reboot(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }

    async fn shutdown(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Err(Status::failed_precondition("upstream says no"))
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

    /// Issues a certificate, returning (cert PEM, key PEM).
    fn issue(&self, sans: &[&str], cn: &str, org: Option<&str>, eku: ExtendedKeyUsagePurpose) -> (String, String) {
        let mut params = CertificateParams::new(sans.iter().map(|&s| s.to_owned()).collect::<Vec<_>>()).unwrap();
        params.distinguished_name.push(DnType::CommonName, cn);
        if let Some(org) = org {
            params.distinguished_name.push(DnType::OrganizationName, org);
        }
        params.extended_key_usages = vec![eku];
        let key = KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &self.issuer).unwrap();
        (cert.pem(), key.serialize_pem())
    }

    fn client(&self, cn: &str, org: Option<&str>) -> (String, String) {
        self.issue(&[], cn, org, ExtendedKeyUsagePurpose::ClientAuth)
    }
}

struct Harness {
    addr: SocketAddr,
    ca: Ca,
    _dir: tempfile::TempDir,
    _stop: oneshot::Sender<()>,
}

impl Harness {
    async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca = Ca::new("test CA");
        let (cert, key) = ca.issue(&["localhost"], "dust-api", None, ExtendedKeyUsagePurpose::ServerAuth);
        let tls_dir = dir.path().join("tls");
        std::fs::create_dir(&tls_dir).unwrap();
        for (name, pem) in [("client-ca.pem", &ca.pem), ("cert.pem", &cert), ("key.pem", &key)] {
            std::fs::write(tls_dir.join(name), pem).unwrap();
        }
        let tls = dust_api::tls::server_config(&tls_dir).unwrap();

        let socket = dir.path().join("control.sock");
        let upstream = UnixListenerStream::new(UnixListener::bind(&socket).unwrap());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(MachineServer::new(FakeDust))
                .serve_with_incoming(upstream),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        tokio::spawn(dust_api::serve(listener, Arc::new(tls), socket, async {
            let _ = stopped.await;
        }));
        Self {
            addr,
            ca,
            _dir: dir,
            _stop: stop,
        }
    }

    async fn client(
        &self,
        ca_pem: &str,
        (cert, key): (String, String),
    ) -> Result<MachineClient<Channel>, tonic::transport::Error> {
        let tls = ClientTlsConfig::new()
            .domain_name("localhost")
            .ca_certificate(Certificate::from_pem(ca_pem))
            .identity(Identity::from_pem(cert, key));
        let channel = Channel::from_shared(format!("https://{}", self.addr))
            .unwrap()
            .tls_config(tls)?
            .connect()
            .await?;
        Ok(MachineClient::new(channel))
    }

    async fn client_with_role(&self, role_org: Option<&str>) -> MachineClient<Channel> {
        self.client(&self.ca.pem, self.ca.client("alice", role_org))
            .await
            .unwrap()
    }
}

#[tokio::test]
async fn reader_can_read_but_not_reboot() {
    let harness = Harness::start().await;
    let mut reader = harness.client_with_role(Some(Role::READER_ORG)).await;

    let version = reader.version(()).await.unwrap().into_inner();
    assert_eq!(version.os_name, "hardened");

    // Server streaming, forwarded through trailers.
    let mut logs = reader.logs(LogsRequest::default()).await.unwrap().into_inner();
    assert!(logs.message().await.unwrap().is_none());

    let denied = reader.reboot(()).await.unwrap_err();
    assert_eq!(denied.code(), Code::PermissionDenied, "{denied:?}");
}

#[tokio::test]
async fn admin_reaches_upstream_statuses() {
    let harness = Harness::start().await;
    let mut admin = harness.client_with_role(Some(Role::ADMIN_ORG)).await;

    admin.reboot(()).await.unwrap();
    let refused = admin.shutdown(()).await.unwrap_err();
    assert_eq!(refused.code(), Code::FailedPrecondition);
    assert_eq!(refused.message(), "upstream says no");
}

#[tokio::test]
async fn client_without_role_is_unauthenticated() {
    let harness = Harness::start().await;
    let mut anonymous = harness.client_with_role(None).await;

    let denied = anonymous.version(()).await.unwrap_err();
    assert_eq!(denied.code(), Code::Unauthenticated, "{denied:?}");
}

#[tokio::test]
async fn unknown_ca_fails_the_handshake() {
    let harness = Harness::start().await;
    let rogue = Ca::new("rogue CA");

    // TLS 1.3 clients may consider the handshake complete before the server has checked their
    // certificate, so the rejection surfaces either when connecting or on the first call.
    match harness
        .client(&harness.ca.pem, rogue.client("mallory", Some(Role::ADMIN_ORG)))
        .await
    {
        Err(_) => {}
        Ok(mut client) => assert!(client.version(()).await.is_err()),
    }
    assert_handshake_rejected(harness.addr, &harness.ca.pem, &rogue).await;
}

/// Checks at the TLS level that the server answers a foreign client certificate with an alert.
async fn assert_handshake_rejected(addr: SocketAddr, ca_pem: &str, rogue: &Ca) {
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
    use tokio::io::AsyncReadExt;

    let (cert, key) = rogue.client("mallory", Some(Role::ADMIN_ORG));
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from_pem_slice(ca_pem.as_bytes()).unwrap())
        .unwrap();
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_client_auth_cert(
            vec![CertificateDer::from_pem_slice(cert.as_bytes()).unwrap()],
            PrivateKeyDer::from_pem_slice(key.as_bytes()).unwrap(),
        )
        .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec()];

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let error = match connector.connect(ServerName::try_from("localhost").unwrap(), tcp).await {
        Err(error) => error,
        Ok(mut tls) => tls.read(&mut [0; 1]).await.unwrap_err(),
    };
    let alert = error.get_ref().and_then(|e| e.downcast_ref::<rustls::Error>());
    assert_eq!(
        alert,
        Some(&rustls::Error::AlertReceived(rustls::AlertDescription::UnknownCA)),
        "{error:?}"
    );
}

#[tokio::test]
async fn missing_tls_material_is_reported() {
    let error = dust_api::tls::server_config(Path::new("/nonexistent")).unwrap_err();
    assert!(format!("{error:#}").contains("client-ca.pem"), "{error:#}");
}

//! The authorizing HTTP/2 reverse proxy.

use std::convert::Infallible;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use dust_proto::Role;
use http::uri::{Authority, Scheme};
use http::{HeaderValue, Request, Response, Uri};
use http_body_util::{Either, Empty};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper_util::client::legacy::Client;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::graceful::{GracefulShutdown, Watcher};
use rustls::ServerConfig;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::access_log::{Entry, Logged};
use crate::authz::{self, Authorized, CertificateError, PermissionDenied};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long in-flight calls (e.g. followed log streams) may run on after a shutdown request.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

type ResponseBody = Logged<Either<Incoming, Empty<Bytes>>>;

/// Accepts mTLS clients on `listener` and forwards their authorized calls to the dust API at
/// `socket`, until `shutdown` completes; then drains open connections.
pub async fn serve(listener: TcpListener, tls: Arc<ServerConfig>, socket: PathBuf, shutdown: impl Future<Output = ()>) {
    let acceptor = TlsAcceptor::from(tls);
    let upstream = Upstream::new(socket);
    let graceful = GracefulShutdown::new();
    let mut shutdown = std::pin::pin!(shutdown);

    loop {
        let (tcp, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(accepted) => accepted,
                Err(error) => {
                    // Typically EMFILE: back off instead of spinning.
                    warn!(%error, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        tokio::spawn(connection(
            acceptor.clone(),
            tcp,
            peer,
            upstream.clone(),
            graceful.watcher(),
        ));
    }

    info!(connections = graceful.count(), "shutting down");
    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown()).await.is_err() {
        warn!("calls still in flight, closing");
    }
}

async fn connection(acceptor: TlsAcceptor, tcp: TcpStream, peer: SocketAddr, upstream: Upstream, watcher: Watcher) {
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => return info!(%peer, %error, "TLS handshake failed"),
        Err(_) => return info!(%peer, "TLS handshake timed out"),
    };
    let session = tls.get_ref().1;
    if session.alpn_protocol() != Some(b"h2") {
        return info!(%peer, "client did not negotiate h2");
    }
    let client = match authz::Client::from_session(session) {
        Ok(client) => Arc::new(client),
        // The verifier makes a client certificate mandatory.
        Err(CertificateError::Missing) => return warn!(%peer, "no client certificate"),
        Err(CertificateError::Unparsable(error)) => return warn!(%peer, %error, "unparsable client certificate"),
    };
    debug!(%peer, ?client, "connected");

    let service = service_fn(move |request| {
        let upstream = upstream.clone();
        let client = client.clone();
        async move { Ok::<_, Infallible>(handle(&upstream, peer, client, request).await) }
    });
    let conn = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .serve_connection(TokioIo::new(tls), service);
    if let Err(error) = watcher.watch(conn).await {
        debug!(%peer, %error, "connection closed");
    }
}

async fn handle(
    upstream: &Upstream,
    peer: SocketAddr,
    client: Arc<authz::Client>,
    request: Request<Incoming>,
) -> Response<ResponseBody> {
    let entry = Entry::new(peer, client.clone(), request.uri().path().to_owned());
    let authz::Client::Authenticated(identity) = &*client else {
        return entry.attach(status(
            Code::Unauthenticated,
            "client certificate carries no hardened role",
        ));
    };
    let response = match identity.authorize(request.uri().path()) {
        Ok(authorized) => match upstream.forward(authorized, request).await {
            Ok(response) => response.map(Either::Left),
            Err(error) => {
                warn!(%peer, error = format!("{error:#}"), "forwarding to dust-init failed");
                status(Code::Unavailable, "dust-init is unavailable")
            }
        },
        Err(PermissionDenied { required: Role::Admin }) => {
            status(Code::PermissionDenied, "method requires the admin role")
        }
        Err(PermissionDenied { required: Role::Reader }) => {
            status(Code::PermissionDenied, "method requires the reader role")
        }
    };
    entry.attach(response)
}

/// gRPC status codes the proxy answers with itself.
#[derive(Debug, Clone, Copy)]
enum Code {
    PermissionDenied = 7,
    Unavailable = 14,
    Unauthenticated = 16,
}

/// A trailers-only gRPC response: headers carrying the status, no body.
fn status(code: Code, message: &'static str) -> Response<Either<Incoming, Empty<Bytes>>> {
    let mut response = Response::new(Either::Right(Empty::new()));
    let headers = response.headers_mut();
    headers.insert(http::header::CONTENT_TYPE, HeaderValue::from_static("application/grpc"));
    headers.insert("grpc-status", HeaderValue::from(code as u16));
    // Our messages are plain ASCII, so no percent-encoding is needed.
    headers.insert("grpc-message", HeaderValue::from_static(message));
    response
}

/// HTTP/2 client of the dust API on its unix socket.
#[derive(Clone)]
struct Upstream {
    client: Client<UnixConnector, Incoming>,
}

impl Upstream {
    fn new(socket: PathBuf) -> Self {
        let client = Client::builder(TokioExecutor::new())
            .http2_only(true)
            .timer(TokioTimer::new())
            .pool_timer(TokioTimer::new())
            .build(UnixConnector(socket.into()));
        Self { client }
    }

    /// Relays an authorized `request` unchanged apart from its URI, which is pointed at the socket.
    async fn forward(&self, _: Authorized, request: Request<Incoming>) -> anyhow::Result<Response<Incoming>> {
        let (mut parts, body) = request.into_parts();
        let mut uri = parts.uri.into_parts();
        uri.scheme = Some(Scheme::HTTP);
        uri.authority = Some(Authority::from_static("dust-init"));
        parts.uri = Uri::from_parts(uri)?;
        Ok(self.client.request(Request::from_parts(parts, body)).await?)
    }
}

/// Connects every request to the same unix socket, whatever its URI.
#[derive(Clone)]
struct UnixConnector(Arc<Path>);

impl tower::Service<Uri> for UnixConnector {
    type Response = TokioIo<UnixStream>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Self::Response>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, _: Uri) -> Self::Future {
        let path = self.0.clone();
        Box::pin(async move { UnixStream::connect(&*path).await.map(TokioIo::new) })
    }
}

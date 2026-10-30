//! The mTLS HTTP/2 server: authorizes every call, then forwards it to machine-controller.

#[cfg(test)]
mod tests;

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use controllers_helpers::Forwarder;
use http::Request;
use http::Response;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service;
use hyper_util::rt::TokioExecutor;
use hyper_util::rt::TokioIo;
use hyper_util::rt::TokioTimer;
use hyper_util::server::graceful::GracefulShutdown;
use hyper_util::server::graceful::Watcher;
use rustls::ServerConfig;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tonic::Status;
use tonic::body::Body;
use tracing::debug;
use tracing::info;
use tracing::warn;

use crate::access_log::Entry;
use crate::access_log::Logged;
use crate::authz::Client;

/// How long a client may take to complete the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// How often HTTP/2 pings check that an idle client is still there.
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(30);
/// How long in-flight calls (e.g. followed log streams) may run on after a shutdown request.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Accepts mTLS clients on `listener` and forwards their authorized calls to the machine-controller
/// listening on `upstream`, until `shutdown` completes; then drains open connections.
pub async fn serve(
    listener: TcpListener,
    tls: Arc<ServerConfig>,
    upstream: &Path,
    shutdown: impl Future<Output = ()>,
) {
    let acceptor = TlsAcceptor::from(tls);
    let forwarder = Forwarder::new(upstream, "machine-controller is unavailable");
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
        tokio::spawn(serve_connection(
            acceptor.clone(),
            tcp,
            peer,
            forwarder.clone(),
            graceful.watcher(),
        ));
    }

    // Closed now, so that a new configuration can listen on the same address.
    drop(listener);
    info!(connections = graceful.count(), "shutting down");
    if tokio::time::timeout(DRAIN_TIMEOUT, graceful.shutdown())
        .await
        .is_err()
    {
        warn!("calls still in flight, closing");
    }
}

/// Serves the calls of the client of `tcp` until it disconnects or `watcher` closes it.
async fn serve_connection(
    acceptor: TlsAcceptor,
    tcp: TcpStream,
    peer: SocketAddr,
    forwarder: Forwarder,
    watcher: Watcher,
) {
    let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(tcp)).await {
        Ok(Ok(tls)) => tls,
        Ok(Err(error)) => return info!(%peer, %error, "TLS handshake failed"),
        Err(_) => return info!(%peer, "TLS handshake timed out"),
    };
    let session = tls.get_ref().1;
    if session.alpn_protocol() != Some(b"h2") {
        return info!(%peer, "client did not negotiate h2");
    }
    let client = match Client::from_session(session) {
        Ok(client) => Arc::new(client),
        // The verifier makes a client certificate mandatory, and parsed it.
        Err(error) => return warn!(%peer, "{error:#}"),
    };
    debug!(%peer, ?client, "connected");

    let service = service::service_fn(move |request| {
        let forwarder = forwarder.clone();
        let client = client.clone();
        async move { Ok::<_, Infallible>(handle(&forwarder, peer, client, request).await) }
    });
    let connection = http2::Builder::new(TokioExecutor::new())
        .timer(TokioTimer::new())
        .keep_alive_interval(KEEP_ALIVE_INTERVAL)
        .serve_connection(TokioIo::new(tls), service);
    if let Err(error) = watcher.watch(connection).await {
        debug!(%peer, %error, "connection closed");
    }
}

/// Forwards `request` if `client` may make it, and logs it.
async fn handle(
    forwarder: &Forwarder,
    peer: SocketAddr,
    client: Arc<Client>,
    request: Request<Incoming>,
) -> Response<Logged<Body>> {
    let entry = Entry::new(peer, client.clone(), request.uri().path().to_owned());
    let response = match client.authorize(request.uri().path()) {
        Ok(()) => forward(forwarder, request).await,
        Err(status) => status.into_http(),
    };
    entry.attach(response)
}

/// Relays an authorized request to machine-controller, and its response.
async fn forward(forwarder: &Forwarder, request: Request<Incoming>) -> Response<Body> {
    match forwarder.forward(request.map(Body::new)).await {
        Ok(response) => response,
        Err(status) => {
            warn!(
                error = status.message(),
                "forwarding to machine-controller failed"
            );
            Status::unavailable("machine-controller is unavailable").into_http()
        }
    }
}

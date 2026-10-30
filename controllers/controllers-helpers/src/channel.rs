//! Connecting to a gRPC API on a unix socket.

use std::io;
use std::path::Path;
use std::sync::Arc;

use http::Uri;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::Channel;
use tonic::transport::Endpoint;
use tower::Service;

/// A channel to the gRPC API on `socket`, serviced's or a service's. Connections wait in
/// the socket's backlog while a socket-activated service starts.
///
/// # Errors
///
/// When the socket cannot be connected to.
pub async fn channel(socket: &Path) -> Result<Channel, tonic::transport::Error> {
    endpoint().connect_with_connector(connector(socket)).await
}

/// A channel to the gRPC API on `socket`, connected on its first call, so that a
/// socket-activated service starts then. A call fails with `unavailable` when the socket cannot
/// be connected to, and the next one tries again; tonic reconnects a broken connection (the
/// service restarted). Created within a tokio runtime.
#[must_use]
pub fn lazy_channel(socket: &Path) -> Channel {
    endpoint().connect_with_connector_lazy(connector(socket))
}

/// The URI is required by tonic but unused: every connection goes to the socket.
fn endpoint() -> Endpoint {
    Endpoint::from_static("http://localhost")
}

/// Connects every request to the same unix socket, whatever its URI.
fn connector(
    socket: &Path,
) -> impl Service<Uri, Response = TokioIo<UnixStream>, Error = io::Error, Future: Send> + Send + 'static
{
    let socket: Arc<Path> = socket.into();
    tower::service_fn(move |_: Uri| {
        let socket = Arc::clone(&socket);
        async move { UnixStream::connect(&*socket).await.map(TokioIo::new) }
    })
}

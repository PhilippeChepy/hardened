//! A gRPC channel to serviced's unix socket (controllers-helpers has the services' own, for
//! their APIs: libserviced only interfaces with serviced).

use std::path::Path;
use std::sync::Arc;

use http::Uri;
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::transport::Channel;
use tonic::transport::Endpoint;

/// A channel to the gRPC API on `socket`. The endpoint's URI is required by tonic but unused:
/// every connection goes to the socket.
pub(crate) async fn connect(socket: &Path) -> Result<Channel, tonic::transport::Error> {
    let socket: Arc<Path> = socket.into();
    let connector = tower::service_fn(move |_: Uri| {
        let socket = Arc::clone(&socket);
        async move { UnixStream::connect(&*socket).await.map(TokioIo::new) }
    });
    Endpoint::from_static("http://localhost")
        .connect_with_connector(connector)
        .await
}

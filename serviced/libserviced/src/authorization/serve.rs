use std::io;

use tonic::transport::Channel;
use tonic::transport::server::Router;

use crate::activation::ActivatedSocket;
use crate::api::serviced_client::ServicedClient;
use crate::authorization::Incoming;
use crate::definition::SocketName;

/// Why serving stopped.
#[derive(Debug, thiserror::Error)]
pub enum ServeError {
    /// The socket could not be registered with tokio.
    #[error("cannot listen on socket {socket}")]
    Listen {
        /// The socket's name.
        socket: SocketName,
        /// Why.
        #[source]
        source: io::Error,
    },
    /// tonic failed (an accept error it does not recover from, for instance).
    #[error("serving socket {socket}")]
    Transport {
        /// The socket's name.
        socket: SocketName,
        /// Why.
        #[source]
        source: tonic::transport::Error,
    },
}

/// Serves `router` on `socket` to the callers its allow-list names, identified by `serviced` (a
/// client of [`connect`](crate::connect)), until `shutdown` completes.
///
/// # Errors
///
/// When the socket cannot be listened on, or tonic fails.
pub async fn serve(
    router: Router,
    socket: ActivatedSocket,
    serviced: ServicedClient<Channel>,
    shutdown: impl Future<Output = ()>,
) -> Result<(), ServeError> {
    let name = socket.name().clone();
    let incoming = Incoming::new(socket, serviced).map_err(|source| ServeError::Listen {
        socket: name.clone(),
        source,
    })?;
    router
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(|source| ServeError::Transport {
            socket: name,
            source,
        })
}

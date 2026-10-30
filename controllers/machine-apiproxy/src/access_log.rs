//! One log line per call, emitted once its response has been fully sent (or abandoned).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::task::ready;
use std::time::Instant;

use http::HeaderValue;
use http::Response;
use hyper::body::Body;
use hyper::body::Frame;
use hyper::body::SizeHint;

use crate::authz::Client;

const GRPC_STATUS: &str = "grpc-status";

/// A call in flight, logged when dropped.
pub struct Entry {
    peer: SocketAddr,
    // Shared by the calls of a connection, each answered by its own task.
    client: Arc<Client>,
    path: String,
    start: Instant,
    grpc_status: Option<HeaderValue>,
}

impl Entry {
    /// Starts the entry of a call of `client`, from `peer`, to the method at `path`.
    #[must_use]
    pub fn new(peer: SocketAddr, client: Arc<Client>, path: String) -> Self {
        Self {
            peer,
            client,
            path,
            start: Instant::now(),
            grpc_status: None,
        }
    }

    /// Attaches the entry to `response`, logging when its body is dropped.
    pub fn attach<B>(mut self, response: Response<B>) -> Response<Logged<B>> {
        self.grpc_status = response.headers().get(GRPC_STATUS).cloned();
        response.map(|inner| Logged { inner, entry: self })
    }
}

impl Drop for Entry {
    fn drop(&mut self) {
        let role = self
            .client
            .role
            .map_or_else(|| "-".to_owned(), |role| role.to_string());
        // A call without grpc-status ended before completing, e.g. cancelled by the client.
        let status = self
            .grpc_status
            .as_ref()
            .and_then(|status| status.to_str().ok())
            .unwrap_or("-");
        tracing::info!(
            peer = %self.peer,
            cn = self.client.common_name.as_deref().unwrap_or("-"),
            role,
            path = self.path,
            grpc_status = status,
            elapsed_ms = self.start.elapsed().as_millis(),
            "call",
        );
    }
}

/// Response body that records the final gRPC status from the trailers.
pub struct Logged<B> {
    inner: B,
    entry: Entry,
}

impl<B: Body + Unpin> Body for Logged<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        if let Some(Ok(frame)) = &frame
            && let Some(status) = frame
                .trailers_ref()
                .and_then(|trailers| trailers.get(GRPC_STATUS))
        {
            this.entry.grpc_status = Some(status.clone());
        }
        Poll::Ready(frame)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

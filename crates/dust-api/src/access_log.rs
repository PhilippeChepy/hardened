//! One log line per call, emitted once its response has been fully sent (or abandoned).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};
use std::time::Instant;

use http::{HeaderValue, Response};
use hyper::body::{Body, Frame, SizeHint};

use crate::authz::Client;

/// A call in flight.
pub struct Entry {
    peer: SocketAddr,
    client: Arc<Client>,
    path: String,
    start: Instant,
    grpc_status: Option<HeaderValue>,
}

impl Entry {
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
        let role = match &*self.client {
            Client::Authenticated(identity) => identity.role().to_string(),
            Client::Unauthenticated { .. } => "-".to_owned(),
        };
        // A call without grpc-status ended before completing, e.g. cancelled by the client.
        let status = self.grpc_status.as_ref().and_then(|s| s.to_str().ok()).unwrap_or("-");
        tracing::info!(
            peer = %self.peer,
            cn = self.client.common_name().unwrap_or("-"),
            role,
            path = self.path,
            grpc_status = status,
            elapsed_ms = self.start.elapsed().as_millis(),
            "call",
        );
    }
}

const GRPC_STATUS: &str = "grpc-status";

/// Response body that records the final gRPC status from the trailers.
pub struct Logged<B> {
    inner: B,
    entry: Entry,
}

impl<B: Body + Unpin> Body for Logged<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        let frame = ready!(Pin::new(&mut this.inner).poll_frame(cx));
        if let Some(Ok(frame)) = &frame
            && let Some(status) = frame.trailers_ref().and_then(|t| t.get(GRPC_STATUS))
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

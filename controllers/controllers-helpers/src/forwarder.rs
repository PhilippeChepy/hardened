//! Relaying gRPC calls unchanged to the API on a unix socket.

use std::convert::Infallible;
use std::future::Future;
use std::marker::PhantomData;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;

use http::Request;
use http::Response;
use tonic::Status;
use tonic::body::Body;
use tonic::server::NamedService;
use tonic::transport::Channel;
use tower::Service;
use tower::ServiceExt;

use crate::channel;

/// Relays calls to the API on a unix socket, and their responses as they come, streamed bodies,
/// statuses and trailers included. Served for the calls of the service `S` names (a generated
/// server, `FooServer<()>`) when it is one.
#[derive(Clone)]
pub struct Forwarder<S = ()> {
    channel: Channel,
    socket: Arc<Path>,
    /// The `unavailable` message of the calls when the socket does not exist.
    absent: &'static str,
    service: PhantomData<fn() -> S>,
}

impl<S> Forwarder<S> {
    /// Forwards to `socket`, connected on the first call. Created within a tokio runtime.
    #[must_use]
    pub fn new(socket: &Path, absent: &'static str) -> Self {
        Self {
            channel: channel::lazy_channel(socket),
            socket: socket.into(),
            absent,
            service: PhantomData,
        }
    }

    /// Relays `request` and returns its response.
    ///
    /// # Errors
    ///
    /// `unavailable` with the absent message when the socket does not exist (serviced creates
    /// none for a service that does not exist or whose condition is false), the status of the
    /// transport error when the call cannot be made.
    pub async fn forward(&self, request: Request<Body>) -> Result<Response<Body>, Status> {
        if !self.socket.exists() {
            return Err(Status::unavailable(self.absent));
        }
        self.channel
            .clone()
            .oneshot(request)
            .await
            .map_err(|e| Status::from_error(e.into()))
    }
}

impl<S: NamedService> NamedService for Forwarder<S> {
    const NAME: &'static str = S::NAME;
}

impl<S: Clone + 'static> Service<Request<Body>> for Forwarder<S> {
    type Response = Response<Body>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, Infallible>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Infallible>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, request: Request<Body>) -> Self::Future {
        let forwarder = self.clone();
        Box::pin(async move {
            let response = forwarder.forward(request).await;
            Ok(response.unwrap_or_else(Status::into_http))
        })
    }
}

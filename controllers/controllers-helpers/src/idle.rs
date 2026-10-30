//! Telling when a socket-activated service is idle, so it can exit: serviced keeps its socket and
//! starts it again on the next connection, which waits in the socket's backlog meanwhile.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use http::Request;
use http::Response;
use http_body_util::BodyExt as _;
use tokio::sync::watch;
use tonic::body::Body;
use tonic::server::NamedService;
use tower::Layer;
use tower::Service;

/// Counts the calls in progress, streamed responses included until their end. Connections do
/// not count: clients keep theirs open between calls.
#[derive(Clone)]
pub struct Idle {
    calls: Arc<watch::Sender<usize>>,
}

impl Default for Idle {
    fn default() -> Self {
        Self {
            calls: Arc::new(watch::Sender::new(0)),
        }
    }
}

impl Idle {
    /// Completes once no call has been in progress for `period`.
    pub async fn wait(&self, period: Duration) {
        let mut calls = self.calls.subscribe();
        loop {
            if calls.wait_for(|&calls| calls == 0).await.is_err() {
                return;
            }
            if tokio::time::timeout(period, calls.changed()).await.is_err() {
                return;
            }
        }
    }

    /// One more call, until the guard is dropped.
    fn begin(&self) -> Guard {
        self.calls.send_modify(|calls| *calls += 1);
        Guard(self.calls.clone())
    }
}

struct Guard(Arc<watch::Sender<usize>>);

impl Drop for Guard {
    fn drop(&mut self) {
        self.0.send_modify(|calls| *calls -= 1);
    }
}

/// Counts the calls of the services it wraps (`.add_service(idle.layer(server))`).
impl<S> Layer<S> for Idle {
    type Service = Counted<S>;

    fn layer(&self, inner: S) -> Self::Service {
        Counted {
            inner,
            idle: self.clone(),
        }
    }
}

/// A service whose calls [`Idle`] counts.
#[derive(Clone)]
pub struct Counted<S> {
    inner: S,
    idle: Idle,
}

impl<S: NamedService> NamedService for Counted<S> {
    const NAME: &'static str = S::NAME;
}

impl<S, B> Service<Request<B>> for Counted<S>
where
    S: Service<Request<B>, Response = Response<Body>>,
    S::Future: Send + 'static,
{
    type Response = Response<Body>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Response<Body>, S::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, request: Request<B>) -> Self::Future {
        let guard = self.idle.begin();
        let response = self.inner.call(request);
        Box::pin(async move {
            let response = response.await?;
            // Dropped with the body, once sent or reset. Named: `let _ = &guard` would not
            // capture it.
            Ok(response.map(|body| {
                Body::new(body.map_frame(move |frame| {
                    let _guard = &guard;
                    frame
                }))
            }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn a_call_lasts_until_its_response_body_is_dropped() {
        // Not an empty body, which tonic would drop at once, the call being over.
        let inner = tower::service_fn(|_: Request<()>| async {
            let body = http_body_util::Full::new(tonic::codegen::Bytes::from("x"));
            Ok::<_, std::convert::Infallible>(Response::new(Body::new(body)))
        });
        let idle = Idle::default();
        let mut service = idle.layer(inner);
        let response = service.call(Request::new(())).await.unwrap();
        assert_eq!(*idle.calls.borrow(), 1);
        drop(response);
        assert_eq!(*idle.calls.borrow(), 0);
    }

    #[tokio::test(start_paused = true)]
    async fn idle_once_no_call_runs_for_the_period() {
        let idle = Idle::default();
        let period = Duration::from_secs(60);
        let call = idle.begin();
        let waited = tokio::spawn({
            let idle = idle.clone();
            async move { idle.wait(period).await }
        });
        tokio::time::sleep(Duration::from_secs(120)).await;
        assert!(!waited.is_finished(), "busy");
        drop(call);
        tokio::time::sleep(Duration::from_secs(30)).await;
        let again = idle.begin();
        drop(again);
        tokio::time::sleep(Duration::from_secs(45)).await;
        assert!(
            !waited.is_finished(),
            "the period starts over after each call"
        );
        tokio::time::sleep(Duration::from_secs(20)).await;
        assert!(waited.is_finished());
    }
}

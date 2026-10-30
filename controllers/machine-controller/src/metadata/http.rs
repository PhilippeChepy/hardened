//! A minimal HTTP/1.1 client for link-local metadata services, at IP addresses reachable only from
//! the instance: neither TLS nor DNS, which would be liabilities this early in boot.
//!
//! Requests are bounded by a timeout and a response size, and transient failures retried with
//! exponential backoff: metadata services are often unreachable for a few seconds after the DHCP
//! lease is acquired.

use std::net::SocketAddr;
use std::time::Duration;

use anyhow::Context;
use http::Request;
use http::StatusCode;
use http::Uri;
use http_body_util::Full;
use http_body_util::LengthLimitError;
use http_body_util::Limited;
use hyper::body::Bytes;
use hyper_util::client::legacy;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::TokioExecutor;

/// For a request, from connecting to reading the whole body.
const TIMEOUT: Duration = Duration::from_secs(5);
/// User-data is capped well below this by metadata services.
const MAX_RESPONSE_SIZE: usize = 1024 * 1024;
/// About 30 seconds of retries (plus request timeouts) before giving up, the first attempt
/// included.
const ATTEMPTS: u32 = 12;
/// Doubled after every failed attempt, up to [`MAX_DELAY`].
const INITIAL_DELAY: Duration = Duration::from_millis(250);
const MAX_DELAY: Duration = Duration::from_secs(4);

/// Why a metadata request failed.
#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("request failed")]
    Transport(#[source] Box<dyn std::error::Error + Send + Sync>),
    #[error("no complete response within {0:?}")]
    Timeout(Duration),
    #[error("unexpected status {0}")]
    Status(StatusCode),
    #[error("response body exceeds {MAX_RESPONSE_SIZE} bytes")]
    TooLarge,
}

impl Failure {
    /// Besides 429 and 5xx, 410 is transient: metadata services answer it until the instance
    /// metadata is available.
    #[must_use]
    fn is_transient(&self) -> bool {
        match self {
            Self::Transport(_) | Self::Timeout(_) => true,
            Self::Status(status) => {
                status.is_server_error()
                    || matches!(*status, StatusCode::TOO_MANY_REQUESTS | StatusCode::GONE)
            }
            Self::TooLarge => false,
        }
    }
}

/// A client of the metadata service at one address.
#[derive(Debug, Clone)]
pub struct Client {
    inner: legacy::Client<HttpConnector, Full<Bytes>>,
    address: SocketAddr,
    timeout: Duration,
    attempts: u32,
    initial_delay: Duration,
}

impl Client {
    /// A client of the service at `address`, with the default timeout and retries.
    #[must_use]
    pub fn new(address: SocketAddr) -> Self {
        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(TIMEOUT));
        Self {
            inner: legacy::Client::builder(TokioExecutor::new()).build(connector),
            address,
            timeout: TIMEOUT,
            attempts: ATTEMPTS,
            initial_delay: INITIAL_DELAY,
        }
    }

    /// GETs `path` (an absolute path, query included), retrying transient failures. A 404 is
    /// `None`, any other non-2xx status an error.
    pub async fn get(&self, path: &str) -> anyhow::Result<Option<Bytes>> {
        let uri: Uri = format!("http://{}{path}", self.address)
            .parse()
            .with_context(|| format!("invalid metadata path {path}"))?;
        let mut delay = self.initial_delay;
        let mut attempt: u32 = 1;
        loop {
            match self.get_once(&uri).await {
                Ok(body) => return Ok(Some(body)),
                Err(Failure::Status(StatusCode::NOT_FOUND)) => return Ok(None),
                Err(error) if error.is_transient() && attempt < self.attempts => {
                    tracing::debug!(%error, attempt, ?delay, "metadata request failed, retrying");
                    tokio::time::sleep(delay).await;
                    delay = delay.saturating_mul(2).min(MAX_DELAY);
                    attempt += 1;
                }
                Err(error) => return Err(anyhow::Error::new(error).context(uri)),
            }
        }
    }

    async fn get_once(&self, uri: &Uri) -> Result<Bytes, Failure> {
        use http_body_util::BodyExt;

        let mut request = Request::new(Full::new(Bytes::new()));
        *request.uri_mut() = uri.clone();
        let exchange = async {
            let response = self
                .inner
                .request(request)
                .await
                .map_err(|e| Failure::Transport(Box::new(e)))?;
            let status = response.status();
            if !status.is_success() {
                return Err(Failure::Status(status));
            }
            match Limited::new(response.into_body(), MAX_RESPONSE_SIZE)
                .collect()
                .await
            {
                Ok(collected) => Ok(collected.to_bytes()),
                Err(e) if e.is::<LengthLimitError>() => Err(Failure::TooLarge),
                Err(e) => Err(Failure::Transport(e)),
            }
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .unwrap_or(Err(Failure::Timeout(self.timeout)))
    }
}

/// A local HTTP server answering through a handler, which gets the request's path and query.
#[cfg(test)]
pub(super) mod mock {
    use std::convert::Infallible;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::time::Duration;

    use http::Request;
    use http::Response;
    use http::StatusCode;
    use http_body_util::Full;
    use hyper::body::Bytes;
    use hyper::body::Incoming;
    use hyper::server::conn::http1;
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use crate::metadata::http::Client;

    /// A response's status and body.
    type Answer = (StatusCode, Vec<u8>);

    /// The server, stopped when dropped.
    pub struct Server {
        client: Client,
        requests: Arc<Mutex<Vec<String>>>,
        task: JoinHandle<()>,
    }

    impl Server {
        /// Starts a server on a free local port.
        pub async fn start(handler: impl Fn(&str) -> Answer + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let mut client = Client::new(listener.local_addr().unwrap());
            client.initial_delay = Duration::from_millis(1);
            client.attempts = 3;
            let requests = Arc::new(Mutex::new(Vec::new()));
            let handler = Arc::new(handler);
            let recorded = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    let handler = Arc::clone(&handler);
                    let recorded = Arc::clone(&recorded);
                    let service = service_fn(move |request: Request<Incoming>| {
                        let target = request.uri().path_and_query().map(ToString::to_string);
                        let target = target.unwrap_or_default();
                        let (status, body) = handler(&target);
                        recorded.lock().unwrap().push(target);
                        let mut response = Response::new(Full::new(Bytes::from(body)));
                        *response.status_mut() = status;
                        async { Ok::<_, Infallible>(response) }
                    });
                    tokio::spawn(async move {
                        let _ = http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            Self {
                client,
                requests,
                task,
            }
        }

        /// A client of this server, with a fast retry policy.
        pub fn client(&self) -> Client {
            self.client.clone()
        }

        /// The paths and queries requested so far.
        pub fn requests(&self) -> Vec<String> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    /// A 200 answer with `body`.
    pub fn ok(body: impl Into<Vec<u8>>) -> Answer {
        (StatusCode::OK, body.into())
    }

    /// A 404 answer.
    pub fn not_found() -> Answer {
        (StatusCode::NOT_FOUND, b"Not Found".to_vec())
    }
}

#[cfg(test)]
mod tests {
    use tokio::net::TcpListener;

    use super::*;
    use crate::metadata::http::mock;
    use crate::metadata::http::mock::Server;

    fn failure(error: &anyhow::Error) -> &Failure {
        error.downcast_ref().expect("a failed request")
    }

    #[tokio::test]
    async fn not_found_is_none() {
        let server = Server::start(|target| match target {
            "/a/b?x=1" => mock::ok("hello"),
            _ => mock::not_found(),
        })
        .await;
        let client = server.client();
        assert_eq!(
            client.get("/a/b?x=1").await.unwrap().as_deref(),
            Some(&b"hello"[..])
        );
        assert_eq!(client.get("/missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn retries_transient_failures_only() {
        let server = Server::start(|target| match target {
            "/flaky" => (StatusCode::SERVICE_UNAVAILABLE, vec![]),
            _ => (StatusCode::FORBIDDEN, vec![]),
        })
        .await;
        let client = server.client();
        let error = client.get("/flaky").await.unwrap_err();
        assert!(matches!(
            failure(&error),
            Failure::Status(StatusCode::SERVICE_UNAVAILABLE)
        ));
        assert_eq!(server.requests().len(), 3, "retried");
        let error = client.get("/forbidden").await.unwrap_err();
        assert!(matches!(
            failure(&error),
            Failure::Status(StatusCode::FORBIDDEN)
        ));
        assert_eq!(
            server.requests().len(),
            4,
            "permanent failures are not retried"
        );
    }

    #[tokio::test]
    async fn caps_response_size() {
        let server = Server::start(|_| mock::ok(vec![b'x'; MAX_RESPONSE_SIZE + 1])).await;
        let error = server.client().get("/big").await.unwrap_err();
        assert!(matches!(failure(&error), Failure::TooLarge), "{error}");
    }

    #[tokio::test]
    async fn times_out_and_reports_unreachable_services() {
        // Accepts connections but never answers.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut client = Client::new(listener.local_addr().unwrap());
        client.attempts = 1;
        client.timeout = Duration::from_millis(50);
        let error = client.get("/").await.unwrap_err();
        assert!(matches!(failure(&error), Failure::Timeout(_)), "{error}");

        drop(listener);
        let mut client = Client::new("127.0.0.1:1".parse().unwrap());
        client.attempts = 1;
        let error = client.get("/").await.unwrap_err();
        assert!(matches!(failure(&error), Failure::Transport(_)), "{error}");
    }
}

//! Minimal plain-HTTP/1.1 client for link-local metadata services (no TLS, no DNS).
//!
//! Metadata services live at fixed IP literals (`169.254.169.254`) and
//! are only reachable from the instance itself, so neither TLS nor name resolution is needed —
//! and both would be a liability this early in boot. Every request is bounded by a timeout and a
//! response size cap, and transient failures (connection errors, timeouts, 410, 429, 5xx) are
//! retried with exponential backoff: metadata services are commonly unreachable for a few seconds
//! after the DHCP lease is acquired.

use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use http::header::{HeaderName, HeaderValue};
use http::{Request, StatusCode, Uri};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Bytes;
use hyper_util::client::legacy::{self, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;

/// Upper bound for a single request, from connecting to reading the whole body.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Largest accepted response body; user-data is capped well below this by metadata services.
pub const MAX_RESPONSE_SIZE: usize = 1024 * 1024;

/// A request header, typically built in a `const` with [`HeaderName::from_static`] and
/// [`HeaderValue::from_static`].
pub type Header = (HeaderName, HeaderValue);

/// A failed metadata request (always a GET).
#[derive(Debug)]
pub struct Error {
    uri: String,
    kind: ErrorKind,
}

#[derive(Debug, thiserror::Error)]
pub enum ErrorKind {
    #[error("invalid metadata endpoint: {0}")]
    InvalidEndpoint(&'static str),
    #[error("request failed")]
    Request(#[source] Box<legacy::Error>),
    #[error("no complete response within {0:?}")]
    Timeout(Duration),
    #[error("unexpected status {0}")]
    Status(StatusCode),
    #[error("response body exceeds {MAX_RESPONSE_SIZE} bytes")]
    TooLarge,
    #[error("reading response body")]
    Body(#[source] Box<dyn std::error::Error + Send + Sync>),
}

impl Error {
    fn new(uri: impl ToString, kind: ErrorKind) -> Self {
        Self {
            uri: uri.to_string(),
            kind,
        }
    }

    #[cfg(test)]
    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    /// The HTTP status, when the server answered with an unexpected one.
    pub fn status(&self) -> Option<StatusCode> {
        match self.kind {
            ErrorKind::Status(status) => Some(status),
            _ => None,
        }
    }

    /// Whether retrying the same request may succeed. Besides 429 and 5xx, this includes 410,
    /// which metadata services answer while the instance metadata is not available yet.
    pub fn is_transient(&self) -> bool {
        match self.kind {
            ErrorKind::Request(_) | ErrorKind::Timeout(_) | ErrorKind::Body(_) => true,
            ErrorKind::Status(status) => {
                status.is_server_error() || matches!(status, StatusCode::TOO_MANY_REQUESTS | StatusCode::GONE)
            }
            ErrorKind::InvalidEndpoint(_) | ErrorKind::TooLarge => false,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.uri, self.kind)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        std::error::Error::source(&self.kind)
    }
}

/// Exponential backoff policy for transient failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Backoff {
    /// Delay before the first retry; doubled after every failed attempt.
    pub initial: Duration,
    /// Upper bound for a single delay.
    pub max_delay: Duration,
    /// Total number of attempts, including the first one.
    pub attempts: u32,
}

impl Backoff {
    /// About 30 seconds of retries (plus request timeouts) before giving up.
    pub const DEFAULT: Self = Self {
        initial: Duration::from_millis(250),
        max_delay: Duration::from_secs(4),
        attempts: 12,
    };

    /// A single attempt.
    #[cfg(test)]
    pub const NONE: Self = Self {
        initial: Duration::ZERO,
        max_delay: Duration::ZERO,
        attempts: 1,
    };
}

impl Default for Backoff {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Runs `op` until it succeeds, fails permanently or `backoff` is exhausted.
pub async fn retry<T, F>(backoff: Backoff, mut op: impl FnMut() -> F) -> Result<T, Error>
where
    F: Future<Output = Result<T, Error>>,
{
    let mut delay = backoff.initial;
    let mut attempt = 1;
    loop {
        match op().await {
            Err(error) if error.is_transient() && attempt < backoff.attempts => {
                tracing::debug!(%error, attempt, ?delay, "metadata request failed, retrying");
                tokio::time::sleep(delay).await;
                delay = delay.saturating_mul(2).min(backoff.max_delay);
                attempt += 1;
            }
            result => return result,
        }
    }
}

/// HTTP/1.1 client bound to one metadata service.
#[derive(Debug, Clone)]
pub struct Client {
    inner: legacy::Client<HttpConnector, Full<Bytes>>,
    /// `http://<ip>[:port][/prefix]`, without trailing slash.
    base: String,
    timeout: Duration,
    backoff: Backoff,
}

impl Client {
    /// Creates a client for the service at `base`, which must be an `http://` URI with an IP
    /// literal host and may carry a path prefix (e.g. `http://169.254.169.254/latest`)
    /// that request paths are appended to.
    pub fn new(base: Uri) -> Result<Self, Error> {
        let invalid = |reason| Error::new(&base, ErrorKind::InvalidEndpoint(reason));
        if base.scheme() != Some(&http::uri::Scheme::HTTP) {
            return Err(invalid("scheme must be http"));
        }
        let host = base.host().unwrap_or_default();
        if host
            .trim_start_matches('[')
            .trim_end_matches(']')
            .parse::<IpAddr>()
            .is_err()
        {
            return Err(invalid("host must be an IP literal"));
        }
        if base.query().is_some() {
            return Err(invalid("must not have a query"));
        }

        let mut connector = HttpConnector::new();
        connector.enforce_http(true);
        connector.set_nodelay(true);
        connector.set_connect_timeout(Some(DEFAULT_TIMEOUT));
        let inner = legacy::Client::builder(TokioExecutor::new()).build(connector);

        let authority = base.authority().map(|a| a.as_str()).unwrap_or_default();
        let prefix = base.path().trim_end_matches('/');
        Ok(Self {
            inner,
            base: format!("http://{authority}{prefix}"),
            timeout: DEFAULT_TIMEOUT,
            backoff: Backoff::DEFAULT,
        })
    }

    /// Overrides the per-request timeout.
    #[cfg(test)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Overrides the retry policy.
    #[cfg(test)]
    pub fn with_backoff(mut self, backoff: Backoff) -> Self {
        self.backoff = backoff;
        self
    }

    /// GETs `path` (relative to the base URI, query included). A 404 yields `None`.
    pub async fn get(&self, path: &str, headers: &[Header]) -> Result<Option<Bytes>, Error> {
        match self.send(path, headers).await {
            Ok(body) => Ok(Some(body)),
            Err(error) if error.status() == Some(StatusCode::NOT_FOUND) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Sends a request, retrying transient failures. Any non-2xx status is an error.
    async fn send(&self, path: &str, headers: &[Header]) -> Result<Bytes, Error> {
        let separator = if path.starts_with('/') { "" } else { "/" };
        let raw = format!("{}{separator}{path}", self.base);
        let uri: Uri = raw
            .parse()
            .map_err(|_| Error::new(&raw, ErrorKind::InvalidEndpoint("invalid request path")))?;
        retry(self.backoff, || self.send_once(&uri, headers)).await
    }

    async fn send_once(&self, uri: &Uri, headers: &[Header]) -> Result<Bytes, Error> {
        let mut request = Request::new(Full::new(Bytes::new()));
        *request.uri_mut() = uri.clone();
        request
            .headers_mut()
            .extend(headers.iter().cloned().map(|(k, v)| (Some(k), v)));

        let exchange = async {
            let response = self
                .inner
                .request(request)
                .await
                .map_err(|e| ErrorKind::Request(Box::new(e)))?;
            let status = response.status();
            if !status.is_success() {
                return Err(ErrorKind::Status(status));
            }
            match Limited::new(response.into_body(), MAX_RESPONSE_SIZE).collect().await {
                Ok(collected) => Ok(collected.to_bytes()),
                Err(e) if e.is::<LengthLimitError>() => Err(ErrorKind::TooLarge),
                Err(e) => Err(ErrorKind::Body(e)),
            }
        };
        tokio::time::timeout(self.timeout, exchange)
            .await
            .unwrap_or(Err(ErrorKind::Timeout(self.timeout)))
            .map_err(|kind| Error::new(uri, kind))
    }
}

/// Test-only HTTP server recording requests and answering through a handler.
#[cfg(test)]
pub(super) mod mock {
    use std::convert::Infallible;
    use std::sync::{Arc, Mutex};

    use http::{HeaderMap, Response, StatusCode, Uri};
    use http_body_util::Full;
    use hyper::body::{Bytes, Incoming};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use tokio::net::TcpListener;
    use tokio::task::JoinHandle;

    use super::{Backoff, Client};

    #[derive(Debug, Clone)]
    pub struct Recorded {
        /// Path and query.
        pub target: String,
        pub headers: HeaderMap,
    }

    impl Recorded {
        pub fn header(&self, name: &str) -> Option<&str> {
            self.headers.get(name).and_then(|v| v.to_str().ok())
        }
    }

    type Handler = dyn Fn(&Recorded) -> (StatusCode, Vec<u8>) + Send + Sync;

    pub struct Server {
        pub uri: Uri,
        requests: Arc<Mutex<Vec<Recorded>>>,
        task: JoinHandle<()>,
    }

    impl Server {
        pub async fn start(handler: impl Fn(&Recorded) -> (StatusCode, Vec<u8>) + Send + Sync + 'static) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let uri = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
            let requests = Arc::new(Mutex::new(Vec::new()));
            let handler: Arc<Handler> = Arc::new(handler);
            let recorded = Arc::clone(&requests);
            let task = tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    let handler = Arc::clone(&handler);
                    let recorded = Arc::clone(&recorded);
                    let service = service_fn(move |request: hyper::Request<Incoming>| {
                        let handler = Arc::clone(&handler);
                        let recorded = Arc::clone(&recorded);
                        async move {
                            let (parts, _) = request.into_parts();
                            let request = Recorded {
                                target: parts.uri.path_and_query().map(ToString::to_string).unwrap_or_default(),
                                headers: parts.headers,
                            };
                            let (status, body) = handler(&request);
                            recorded.lock().unwrap().push(request);
                            let mut response = Response::new(Full::new(Bytes::from(body)));
                            *response.status_mut() = status;
                            Ok::<_, Infallible>(response)
                        }
                    });
                    tokio::spawn(async move {
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            Self { uri, requests, task }
        }

        /// A client for this server with a fast retry policy.
        pub fn client(&self) -> Client {
            self.client_with_prefix("")
        }

        pub fn client_with_prefix(&self, prefix: &str) -> Client {
            let base = format!("{}{prefix}", self.uri).parse().unwrap();
            Client::new(base).unwrap().with_backoff(Backoff {
                initial: std::time::Duration::from_millis(1),
                max_delay: std::time::Duration::from_millis(4),
                attempts: 3,
            })
        }

        pub fn requests(&self) -> Vec<Recorded> {
            self.requests.lock().unwrap().clone()
        }
    }

    impl Drop for Server {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    pub fn ok(body: impl Into<Vec<u8>>) -> (StatusCode, Vec<u8>) {
        (StatusCode::OK, body.into())
    }

    pub fn not_found() -> (StatusCode, Vec<u8>) {
        (StatusCode::NOT_FOUND, b"Not Found".to_vec())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::mock::{self, Server};
    use super::*;

    #[test]
    fn rejects_non_link_local_style_endpoints() {
        for base in [
            "https://169.254.169.254",
            "http://metadata.google.internal",
            "http://10.0.0.1/?a=b",
        ] {
            assert!(Client::new(base.parse().unwrap()).is_err(), "{base}");
        }
        assert!(Client::new(Uri::from_static("http://[fd00:ec2::254]")).is_ok());
    }

    #[tokio::test]
    async fn get_joins_paths_and_sends_headers() {
        let server = Server::start(|r| match r.target.as_str() {
            "/prefix/a/b?x=1" => mock::ok("hello"),
            _ => mock::not_found(),
        })
        .await;
        let client = server.client_with_prefix("prefix/");
        let header = (HeaderName::from_static("x-test"), HeaderValue::from_static("yes"));
        let body = client.get("a/b?x=1", &[header]).await.unwrap();
        assert_eq!(body.as_deref(), Some(&b"hello"[..]));
        assert_eq!(client.get("/missing", &[]).await.unwrap(), None);
        assert_eq!(server.requests()[0].header("x-test"), Some("yes"));
    }

    #[tokio::test]
    async fn retries_transient_failures_only() {
        let calls = std::sync::Arc::new(AtomicU32::new(0));
        let counter = std::sync::Arc::clone(&calls);
        let server = Server::start(move |r| match r.target.as_str() {
            "/flaky" if counter.fetch_add(1, Ordering::SeqCst) == 0 => (StatusCode::SERVICE_UNAVAILABLE, vec![]),
            "/flaky" => mock::ok("up"),
            _ => (StatusCode::FORBIDDEN, vec![]),
        })
        .await;
        let client = server.client();
        assert_eq!(client.get("/flaky", &[]).await.unwrap().as_deref(), Some(&b"up"[..]));
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        let error = client.get("/forbidden", &[]).await.unwrap_err();
        assert_eq!(error.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(server.requests().len(), 3, "permanent failures are not retried");
    }

    #[tokio::test]
    async fn caps_response_size() {
        let server = Server::start(|_| mock::ok(vec![b'x'; MAX_RESPONSE_SIZE + 1])).await;
        let error = server.client().get("/big", &[]).await.unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::TooLarge), "{error}");
    }

    #[tokio::test]
    async fn times_out_and_reports_unreachable_services() {
        // Accepts connections but never answers.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap()).parse().unwrap();
        let client = Client::new(base)
            .unwrap()
            .with_backoff(Backoff::NONE)
            .with_timeout(Duration::from_millis(50));
        let error = client.get("/", &[]).await.unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Timeout(_)), "{error}");
        assert!(error.is_transient());

        drop(listener);
        let base = format!("http://{}", "127.0.0.1:1").parse().unwrap();
        let error = Client::new(base)
            .unwrap()
            .with_backoff(Backoff::NONE)
            .get("/", &[])
            .await
            .unwrap_err();
        assert!(matches!(error.kind(), ErrorKind::Request(_)), "{error}");
    }
}

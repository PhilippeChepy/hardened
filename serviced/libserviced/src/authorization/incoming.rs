use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::Context;
use std::task::Poll;
use std::time::Duration;

use tokio::net::UnixListener;
use tokio::net::UnixStream;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tokio_stream::Stream;
use tonic::Code;
use tonic::transport::Channel;

use crate::activation::ActivatedSocket;
use crate::api::ProcessRef;
use crate::api::serviced_client::ServicedClient;
use crate::authorization::Caller;
use crate::authorization::CallerStream;
use crate::definition;
use crate::definition::ServiceName;
use crate::definition::SocketName;

/// How long serviced may take to identify a caller before its connection is dropped.
const IDENTIFY_TIMEOUT: Duration = Duration::from_secs(5);

/// Connections waiting for tonic.
const QUEUE: usize = 16;

/// The connections of allowed callers to a socket, for tonic's `serve_with_incoming`, or for a
/// service serving another protocol on it.
///
/// A background task accepts connections and identifies their callers concurrently, so a slow
/// identification does not hold up the others; it stops when this is dropped.
#[derive(Debug)]
pub struct Incoming {
    receiver: mpsc::Receiver<io::Result<CallerStream>>,
}

impl Incoming {
    /// Accepts connections to `socket`, identifying callers with `serviced`.
    ///
    /// # Errors
    ///
    /// When the socket cannot be made non-blocking for tokio.
    ///
    /// # Panics
    ///
    /// Outside a tokio runtime.
    pub fn new(socket: ActivatedSocket, serviced: ServicedClient<Channel>) -> io::Result<Self> {
        let (name, allow, listener) = socket.into_parts();
        listener.set_nonblocking(true)?;
        let listener = UnixListener::from_std(listener)?;
        let (sender, receiver) = mpsc::channel(QUEUE);
        let gate = Arc::new(Gate {
            socket: name,
            allow,
            serviced,
        });
        tokio::spawn(accept(listener, gate, sender));
        Ok(Self { receiver })
    }
}

impl Stream for Incoming {
    type Item = io::Result<CallerStream>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<io::Result<CallerStream>>> {
        self.receiver.poll_recv(context)
    }
}

/// What a connection must pass.
struct Gate {
    socket: SocketName,
    allow: Vec<ServiceName>,
    serviced: ServicedClient<Channel>,
}

/// Why a caller could not be identified.
#[derive(Debug, thiserror::Error)]
enum Unidentified {
    #[error("no peer credentials: {0}")]
    Credentials(#[source] io::Error),
    #[error("the peer has no pid in this pid namespace")]
    NoPid,
    #[error("the process belongs to no service")]
    NoService,
    #[error("serviced named an invalid service: {0}")]
    InvalidName(#[source] definition::Error),
    #[error("serviced: {0}")]
    Serviced(#[source] tonic::Status),
    #[error("serviced did not answer in time")]
    Timeout,
}

/// Accepts connections until the [`Incoming`] is dropped, which aborts the identifications in
/// progress.
async fn accept(
    listener: UnixListener,
    gate: Arc<Gate>,
    sender: mpsc::Sender<io::Result<CallerStream>>,
) {
    let mut identifications = JoinSet::new();
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    identifications.spawn(admit(stream, Arc::clone(&gate), sender.clone()));
                }
                // tonic decides which errors end serving.
                Err(error) => {
                    if sender.send(Err(error)).await.is_err() {
                        return;
                    }
                }
            },
            Some(_) = identifications.join_next(), if !identifications.is_empty() => {}
            () = sender.closed() => return,
        }
    }
}

/// Hands the connection to tonic if its caller is allowed, and drops it otherwise.
async fn admit(
    stream: UnixStream,
    gate: Arc<Gate>,
    sender: mpsc::Sender<io::Result<CallerStream>>,
) {
    match identify(&stream, &gate).await {
        Ok(caller) if gate.allow.contains(caller.service()) => {
            // An error means serving stopped.
            let _ = sender.send(Ok(CallerStream::new(stream, caller))).await;
        }
        Ok(caller) => tracing::warn!(
            socket = %gate.socket,
            caller = %caller.service(),
            pid = caller.pid(),
            "refused a caller not in the socket's allow-list"
        ),
        Err(error) => tracing::warn!(
            socket = %gate.socket,
            error = &error as &dyn std::error::Error,
            "refused an unidentified caller"
        ),
    }
}

/// Asks serviced which service the peer of `stream` belongs to. Nothing is cached: a pid can be
/// reused.
async fn identify(stream: &UnixStream, gate: &Gate) -> Result<Caller, Unidentified> {
    let credentials = stream.peer_cred().map_err(Unidentified::Credentials)?;
    let pid = credentials
        .pid()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or(Unidentified::NoPid)?;
    let mut serviced = gate.serviced.clone();
    let service = tokio::time::timeout(
        IDENTIFY_TIMEOUT,
        serviced.identify_process(ProcessRef { pid }),
    )
    .await
    .map_err(|_| Unidentified::Timeout)?
    .map_err(|status| match status.code() {
        Code::NotFound => Unidentified::NoService,
        _ => Unidentified::Serviced(status),
    })?
    .into_inner();
    let service = service.name.parse().map_err(Unidentified::InvalidName)?;
    Ok(Caller::new(service, pid))
}

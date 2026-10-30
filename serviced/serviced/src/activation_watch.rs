//! Waiting for the first connection to a socket-activated service that is not running, on one of
//! its activating sockets. serviced only polls them: the connection waits in the backlog until the
//! service, started then, accepts it on the socket it inherits.

use std::io;
use std::os::fd::OwnedFd;

use libserviced::definition::{ServiceName, SocketName};
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use tokio::task::JoinSet;
use tracing::warn;

use crate::engine::Event;
use crate::service_sockets::Listener;

/// Watches the activating sockets among `listeners`, the sockets of `service`, until one has a
/// connection waiting, then sends [`Event::Activated`] to `events` once. Stops watching when the
/// set is dropped.
pub fn start(
    service: &ServiceName,
    listeners: &[Listener],
    events: &mpsc::UnboundedSender<Event>,
) -> io::Result<JoinSet<()>> {
    let mut tasks = JoinSet::new();
    for listener in listeners.iter().filter(|listener| listener.socket.activate) {
        // A copy of its own, registered with tokio: the socket stays blocking for the service,
        // which shares its open file description.
        let copy = listener.fd.try_clone()?;
        // SAFETY: `copy` is an open fd the `AsyncFd` owns, so it stays open, the same, until the
        // `AsyncFd` is dropped.
        let fd = unsafe { AsyncFd::register_with_interest(copy, Interest::READABLE) }?;
        let service = service.clone();
        let socket = listener.socket.name.clone();
        tasks.spawn(wait(fd, service, socket, events.clone()));
    }
    Ok(tasks)
}

/// Sends [`Event::Activated`] once `fd` has a connection waiting.
async fn wait(
    fd: AsyncFd<OwnedFd>,
    service: ServiceName,
    socket: SocketName,
    events: mpsc::UnboundedSender<Event>,
) {
    match fd.readable().await {
        Ok(_) => {
            let _ = events.send(Event::Activated { service, socket });
        }
        Err(e) => warn!(service = %service, %socket, "cannot watch the socket: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn a_connection_activates_once() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("api.sock");
        let listener = Listener {
            socket: toml::from_str(&format!(
                "name = \"api\"\npath = {path:?}\nactivate = true\n"
            ))
            .unwrap(),
            fd: Arc::new(OwnedFd::from(UnixListener::bind(&path).unwrap())),
        };
        let service: ServiceName = "trust-controller".parse().unwrap();
        let (events, mut received) = mpsc::unbounded_channel();
        let _watch = start(&service, std::slice::from_ref(&listener), &events).unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(received.try_recv().is_err(), "no connection yet");

        let _client = UnixStream::connect(&path).unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(&event, Event::Activated { service, socket }
                if service.as_str() == "trust-controller" && socket.as_str() == "api"),
            "{event:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(received.try_recv().is_err(), "once");

        // Not accepted: the service is to accept it.
        let std_listener = UnixListener::from(listener.fd.try_clone().unwrap());
        std_listener.set_nonblocking(true).unwrap();
        assert!(
            std_listener.accept().is_ok(),
            "still waiting in the backlog"
        );
    }
}

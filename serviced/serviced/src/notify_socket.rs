//! The notify socket of a service (`<DIR>/<service>`, `NOTIFY_SOCKET` in its processes'
//! environment): a datagram socket serviced reads, so it knows which service sent what. It is the
//! service's (its sandbox's user) and no one else's, and each datagram comes with its sender's pid
//! (`SO_PASSCRED`): only those of the service's processes are taken.

use std::io;
use std::io::{ErrorKind, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use libserviced::definition::ServiceName;
use rustix::fs::{Gid, Mode, Uid};
use rustix::net::{RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags};
use tokio::io::Interest;
use tokio::net::UnixDatagram;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::{debug, warn};

use crate::caller::Resolver;
use crate::engine::Event;
use crate::notification::Notification;

/// Where the notify sockets are.
pub const DIR: &str = "/run/serviced/notify";
/// A larger datagram is cut: notifications are a few short lines.
const MAX_DATAGRAM: usize = 4096;

/// A service's notify socket, read until dropped (then removed).
pub struct NotifySocket {
    path: PathBuf,
    reader: JoinHandle<()>,
}

impl NotifySocket {
    /// Binds the notify socket of `service` in `dir`, for its processes, owned by `user` (as uid
    /// and gid). Their notifications become [`Event::Notified`] in `events`, those of other
    /// processes (by `resolve`) are ignored.
    pub fn bind(
        dir: &Path,
        service: &ServiceName,
        user: u32,
        resolve: Resolver,
        events: mpsc::UnboundedSender<Event>,
    ) -> anyhow::Result<Self> {
        let path = dir.join(service.as_str());
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != ErrorKind::NotFound
        {
            return Err(e).with_context(|| format!("removing {}", path.display()));
        }
        let socket = bind(&path, user).inspect_err(|_| {
            let _ = std::fs::remove_file(&path);
        })?;
        Ok(Self {
            path,
            reader: tokio::spawn(read(socket, service.clone(), resolve, events)),
        })
    }

    /// The socket's path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Makes the socket `user`'s: the service's sandbox user may have changed.
    pub fn chown(&self, user: u32) -> anyhow::Result<()> {
        own(&self.path, user)
    }
}

/// Binds a datagram socket at `path`, `user`'s with mode 0600, receiving its senders' pids.
fn bind(path: &Path, user: u32) -> anyhow::Result<UnixDatagram> {
    let socket = std::os::unix::net::UnixDatagram::bind(path)
        .with_context(|| format!("binding {}", path.display()))?;
    rustix::net::sockopt::set_socket_passcred(&socket, true).context("SO_PASSCRED")?;
    socket.set_nonblocking(true)?;
    own(path, user)?;
    Ok(UnixDatagram::from_std(socket)?)
}

/// Makes `path` `user`'s (as uid and gid), mode 0600.
fn own(path: &Path, user: u32) -> anyhow::Result<()> {
    rustix::fs::chown(path, Some(Uid::from_raw(user)), Some(Gid::from_raw(user)))
        .with_context(|| format!("chown {}", path.display()))?;
    rustix::fs::chmod(path, Mode::from_raw_mode(0o600))
        .with_context(|| format!("chmod {}", path.display()))?;
    Ok(())
}

impl Drop for NotifySocket {
    fn drop(&mut self) {
        self.reader.abort();
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Reads the notifications of `socket`, service `service`'s, until it fails.
async fn read(
    socket: UnixDatagram,
    service: ServiceName,
    resolve: Resolver,
    events: mpsc::UnboundedSender<Event>,
) {
    let mut datagram = vec![0; MAX_DATAGRAM];
    loop {
        if let Err(e) = socket.readable().await {
            warn!(service = %service, error = %e, "notify socket failed");
            return;
        }
        let received = socket.try_io(Interest::READABLE, || receive(&socket, &mut datagram));
        let (length, sender) = match received {
            Ok(received) => received,
            Err(e) if e.kind() == ErrorKind::WouldBlock => continue,
            Err(e) => {
                warn!(service = %service, error = %e, "notify socket failed");
                return;
            }
        };
        let Some(pid) = sender else {
            debug!(service = %service, "notification without credentials, ignored");
            continue;
        };
        if resolve(pid).as_ref() != Some(&service) {
            debug!(service = %service, pid, "notification from another service's process, ignored");
            continue;
        }
        let notification = Notification::parse(&datagram[..length]);
        let _ = events.send(Event::Notified {
            service: service.clone(),
            pid,
            notification,
        });
    }
}

/// Receives a datagram into `buffer`: its length (cut to the buffer's), and its sender's pid.
/// File descriptors sent along are closed.
fn receive(socket: impl AsFd, buffer: &mut [u8]) -> io::Result<(usize, Option<u32>)> {
    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmCredentials(1))];
    let mut ancillary = RecvAncillaryBuffer::new(&mut space);
    let message = rustix::net::recvmsg(
        socket,
        &mut [IoSliceMut::new(buffer)],
        &mut ancillary,
        RecvFlags::DONTWAIT | RecvFlags::CMSG_CLOEXEC,
    )?;
    let mut sender = None;
    for message in ancillary.drain() {
        if let RecvAncillaryMessage::ScmCredentials(credentials) = message {
            sender = u32::try_from(credentials.pid.as_raw_nonzero().get()).ok();
        }
    }
    Ok((message.bytes.min(buffer.len()), sender))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[tokio::test]
    async fn notifications_of_the_service_s_processes() {
        let user = rustix::process::getuid().as_raw();
        if rustix::process::getgid().as_raw() != user {
            // The socket gets the user as its uid and gid, which needs both to be the test
            // user's, or root.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let service: ServiceName = "web".parse().unwrap();
        let me = std::process::id();
        let (events, mut received) = mpsc::unbounded_channel();
        // This process is the service's; any other is not.
        let resolve: Resolver = Arc::new(move |pid| (pid == me).then(|| "web".parse().unwrap()));
        let other: ServiceName = "other".parse().unwrap();
        let others =
            NotifySocket::bind(dir.path(), &other, user, resolve.clone(), events.clone()).unwrap();
        let socket = NotifySocket::bind(dir.path(), &service, user, resolve, events).unwrap();
        assert_eq!(socket.path(), dir.path().join("web"));
        let mode = std::fs::metadata(socket.path()).unwrap();
        assert_eq!(
            std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o777,
            0o600
        );

        let sender = std::os::unix::net::UnixDatagram::unbound().unwrap();
        sender.send_to(b"READY=1", others.path()).unwrap();
        sender
            .send_to(b"READY=1\nSTATUS=up", socket.path())
            .unwrap();
        let event = tokio::time::timeout(Duration::from_secs(5), received.recv())
            .await
            .unwrap()
            .unwrap();
        let Event::Notified {
            service,
            pid,
            notification,
        } = event
        else {
            panic!("{event:?}");
        };
        assert_eq!(service.as_str(), "web");
        assert_eq!(pid, me);
        assert!(notification.ready);
        assert_eq!(notification.status.as_deref(), Some("up"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            received.try_recv().is_err(),
            "the notification of another service's process is ignored"
        );

        let path = socket.path().to_owned();
        drop(socket);
        assert!(!path.exists(), "removed with the service");
    }
}

//! A logind for kubelet's graceful node shutdown, which takes a delay lock from logind over the
//! D-Bus system bus and stops the node's pods when logind announces the shutdown
//! (`PrepareForShutdown`). There is neither D-Bus nor logind: this answers, as both, the few calls
//! kubelet makes, on a socket only kubelet may connect to, and holds a delay lock of serviced's
//! (`WatchShutdown`) for as long as kubelet holds its own, so that serviced's announcement of a
//! shutdown becomes `PrepareForShutdown`.

use std::io;
use std::io::IoSlice;
use std::mem::MaybeUninit;
use std::os::fd::AsFd;
use std::os::fd::BorrowedFd;
use std::os::fd::OwnedFd;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use kubelet_controller::Duration;
use libserviced::activation::ActivatedSocket;
use libserviced::api::ShutdownLock;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::authorization::Incoming;
use rustix::net::SendAncillaryBuffer;
use rustix::net::SendAncillaryMessage;
use rustix::net::SendFlags;
use tokio::io::Interest;
use tokio::net::UnixStream;
use tokio::sync::watch;
use tokio_stream::StreamExt as _;
use tonic::transport::Channel;

use crate::dbus_message::Body;
use crate::dbus_message::Invalid;
use crate::dbus_message::Kind;
use crate::dbus_message::Message;
use crate::dbus_message::NO_REPLY_EXPECTED;

const BUS: &str = "org.freedesktop.DBus";
const LOGIND: &str = "org.freedesktop.login1";
const LOGIND_PATH: &str = "/org/freedesktop/login1";
const MANAGER: &str = "org.freedesktop.login1.Manager";
const PROPERTIES: &str = "org.freedesktop.DBus.Properties";
/// Authentication accepted, with the server's GUID (`hardened-logind`, in hexadecimal).
const OK: &str = "OK 68617264656e65642d6c6f67696e6400";
/// The longest authentication line accepted.
const MAX_LINE: usize = 1024;
/// Added to kubelet's grace period for serviced's lock: kubelet releases its own once its pods
/// stopped, a moment after the period at most.
const MARGIN_SECONDS: u64 = 5;

/// The logind kubelet talks to.
pub struct Logind {
    serviced: ServicedClient<Channel>,
    /// kubelet's `shutdownGracePeriod`, which logind's `InhibitDelayMaxUSec` must reach.
    grace_period: watch::Receiver<Option<Duration>>,
    /// Whether serviced announced a shutdown.
    shutting_down: watch::Sender<bool>,
    /// The last unique name given to a connection.
    names: AtomicU32,
}

/// Why a connection ends early.
#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Invalid(#[from] Invalid),
    #[error("authentication: {0}")]
    Authentication(&'static str),
}

impl Logind {
    /// A logind holding serviced's delay locks through `serviced`, while kubelet runs with
    /// `grace_period`.
    #[must_use]
    pub fn new(
        serviced: ServicedClient<Channel>,
        grace_period: watch::Receiver<Option<Duration>>,
    ) -> Self {
        Self {
            serviced,
            grace_period,
            shutting_down: watch::Sender::new(false),
            names: AtomicU32::new(0),
        }
    }

    /// Answers the connections to `socket` its allow-list permits (kubelet's).
    ///
    /// # Errors
    ///
    /// When the socket cannot be listened on.
    pub async fn serve(self: Arc<Self>, socket: ActivatedSocket) -> io::Result<()> {
        let mut incoming = Incoming::new(socket, self.serviced.clone())?;
        while let Some(accepted) = incoming.next().await {
            match accepted {
                Ok(connection) => {
                    let (stream, _) = connection.into_parts();
                    let logind = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(error) = logind.connection(stream).await {
                            tracing::warn!(%error, "kubelet's D-Bus connection failed");
                        }
                    });
                }
                Err(error) => tracing::warn!(%error, "accepting a D-Bus connection"),
            }
        }
        Ok(())
    }

    /// Authenticates the connection, then answers its calls and sends it `PrepareForShutdown`
    /// once it asked for the signal, until it closes.
    async fn connection(self: Arc<Self>, stream: UnixStream) -> Result<(), Failure> {
        let mut buffer = Vec::new();
        authenticate(&stream, &mut buffer).await?;
        let number = self.names.fetch_add(1, Ordering::Relaxed) + 1;
        let mut connection = Connection {
            stream,
            name: format!(":1.{number}"),
            serial: 0,
            watching: false,
        };
        let mut shutting_down = self.shutting_down.subscribe();
        loop {
            while let Some((message, length)) = Message::parse(&buffer)? {
                buffer.drain(..length);
                if message.kind == Kind::MethodCall {
                    self.call(&mut connection, &message).await?;
                }
            }
            tokio::select! {
                read = read_some(&connection.stream, &mut buffer) => {
                    if read? == 0 {
                        return Ok(());
                    }
                }
                changed = shutting_down.changed() => {
                    if changed.is_err() {
                        return Ok(());
                    }
                    let active = *shutting_down.borrow_and_update();
                    if connection.watching {
                        connection.prepare_for_shutdown(active).await?;
                    }
                }
            }
        }
    }

    /// Answers `call`.
    async fn call(&self, connection: &mut Connection, call: &Message) -> Result<(), Failure> {
        let interface = call.interface.as_deref().unwrap_or_default();
        let member = call.member.as_deref().unwrap_or_default();
        let serial = connection.next_serial();
        let (reply, fd) = match (interface, member) {
            (BUS, "Hello") => {
                let mut reply = Message::reply_to(call, serial, BUS);
                reply.destination = Some(connection.name.clone());
                reply.signature = "s".to_owned();
                reply.body = Body::default().string(&connection.name).into_bytes();
                (reply, None)
            }
            (BUS, "AddMatch") => {
                connection.watching = true;
                (Message::reply_to(call, serial, BUS), None)
            }
            (BUS, "RemoveMatch") => (Message::reply_to(call, serial, BUS), None),
            (PROPERTIES, "Get") => (self.property(call, serial)?, None),
            (MANAGER, "Inhibit") => self.inhibit(call, serial)?,
            _ => {
                tracing::debug!(%call, "unknown D-Bus method");
                let error = Message::error_to(
                    call,
                    serial,
                    LOGIND,
                    "org.freedesktop.DBus.Error.UnknownMethod",
                    &format!("{interface}.{member} is not implemented"),
                );
                (error, None)
            }
        };
        if call.flags & NO_REPLY_EXPECTED == 0 {
            connection
                .send(&reply, fd.as_ref().map(AsFd::as_fd))
                .await?;
        }
        Ok(())
    }

    /// `InhibitDelayMaxUSec`, kubelet's grace period: it would write a logind configuration to
    /// raise a shorter one. 0 when kubelet has none, and does not take a lock.
    fn property(&self, call: &Message, serial: u32) -> Result<Message, Invalid> {
        let arguments = call.strings(2)?;
        let [interface, property] = arguments.as_slice() else {
            return Err(Invalid("arguments"));
        };
        if call.path.as_deref() != Some(LOGIND_PATH)
            || interface != MANAGER
            || property != "InhibitDelayMaxUSec"
        {
            return Ok(Message::error_to(
                call,
                serial,
                LOGIND,
                "org.freedesktop.DBus.Error.UnknownProperty",
                &format!("{interface}.{property} is not implemented"),
            ));
        }
        let micros = self
            .grace_period
            .borrow()
            .map_or(0, |period| period.millis().saturating_mul(1000));
        let mut reply = Message::reply_to(call, serial, LOGIND);
        reply.signature = "v".to_owned();
        reply.body = Body::default().variant_u64(micros).into_bytes();
        Ok(reply)
    }

    /// A delay lock on shutdown: the reply carries one end of a socket pair, the lock is held
    /// until kubelet closes it (or exits).
    fn inhibit(&self, call: &Message, serial: u32) -> Result<(Message, Option<OwnedFd>), Failure> {
        let arguments = call.strings(4)?;
        let [what, who, _, mode] = arguments.as_slice() else {
            return Err(Invalid("arguments").into());
        };
        if mode != "delay" || !what.split(':').any(|what| what == "shutdown") {
            let error = Message::error_to(
                call,
                serial,
                LOGIND,
                "org.freedesktop.DBus.Error.NotSupported",
                "only delay locks on shutdown are supported",
            );
            return Ok((error, None));
        }
        let (ours, theirs) = UnixStream::pair()?;
        let theirs = OwnedFd::from(theirs.into_std()?);
        tokio::spawn(self.hold(ours, who.clone()));
        let mut reply = Message::reply_to(call, serial, LOGIND);
        reply.signature = "h".to_owned();
        reply.unix_fds = 1;
        reply.body = Body::default().u32(0).into_bytes();
        Ok((reply, Some(theirs)))
    }

    /// Holds a lock of serviced's while `released` stays open, and relays its announcement.
    fn hold(&self, released: UnixStream, who: String) -> impl Future<Output = ()> + use<> {
        let mut serviced = self.serviced.clone();
        let delay = *self.grace_period.borrow();
        let shutting_down = self.shutting_down.clone();
        async move {
            let delay_seconds = delay
                .map(|period| period.millis().div_ceil(1000) + MARGIN_SECONDS)
                .and_then(|seconds| u32::try_from(seconds).ok());
            let mut events = match delay_seconds {
                Some(delay_seconds) => {
                    match serviced
                        .watch_shutdown(ShutdownLock { delay_seconds })
                        .await
                    {
                        Ok(events) => Some(events.into_inner()),
                        Err(status) => {
                            tracing::warn!(error = status.message(), "no delay lock of serviced's");
                            None
                        }
                    }
                }
                None => None,
            };
            tracing::info!(who, delay_seconds, "shutdown delay lock taken");
            loop {
                let event = async {
                    match &mut events {
                        Some(events) => events.message().await,
                        None => std::future::pending().await,
                    }
                };
                tokio::select! {
                    () = closed(&released) => break,
                    event = event => match event {
                        Ok(Some(event)) => {
                            if event.shutting_down {
                                tracing::info!("serviced announced a shutdown, kubelet is told");
                                shutting_down.send_replace(true);
                            }
                        }
                        Ok(None) | Err(_) => {
                            tracing::warn!("serviced's delay lock ended");
                            events = None;
                        }
                    },
                }
            }
            tracing::info!(who, "shutdown delay lock released");
        }
    }
}

/// An authenticated connection.
struct Connection {
    stream: UnixStream,
    /// Its unique name, which `Hello` gives.
    name: String,
    serial: u32,
    /// Whether it asked for signals (`AddMatch`).
    watching: bool,
}

impl Connection {
    fn next_serial(&mut self) -> u32 {
        self.serial = self.serial.wrapping_add(1).max(1);
        self.serial
    }

    async fn prepare_for_shutdown(&mut self, active: bool) -> io::Result<()> {
        let mut signal = Message::new(Kind::Signal, self.next_serial());
        signal.path = Some(LOGIND_PATH.to_owned());
        signal.interface = Some(MANAGER.to_owned());
        signal.member = Some("PrepareForShutdown".to_owned());
        signal.sender = Some(LOGIND.to_owned());
        signal.signature = "b".to_owned();
        signal.body = Body::default().boolean(active).into_bytes();
        self.send(&signal, None).await
    }

    /// Sends `message`, with `fd` if any.
    async fn send(&self, message: &Message, fd: Option<BorrowedFd<'_>>) -> io::Result<()> {
        let bytes = message.encode();
        let mut sent = 0;
        while sent < bytes.len() {
            let rest = bytes.get(sent..).unwrap_or_default();
            sent += self
                .stream
                .async_io(Interest::WRITABLE, || {
                    let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
                    let mut control = SendAncillaryBuffer::new(&mut space);
                    // The fd goes with the message's first byte.
                    let fds: Vec<BorrowedFd<'_>> = fd.filter(|_| sent == 0).into_iter().collect();
                    if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(&fds)) {
                        return Err(io::Error::other("no room for the fd"));
                    }
                    Ok(rustix::net::sendmsg(
                        &self.stream,
                        &[IoSlice::new(rest)],
                        &mut control,
                        SendFlags::NOSIGNAL,
                    )?)
                })
                .await?;
        }
        Ok(())
    }
}

/// The SASL exchange: a NUL byte, then `EXTERNAL` accepted (serviced identified the caller when
/// it connected), unix fds agreed on, until `BEGIN`. What follows it stays in `buffer`.
async fn authenticate(stream: &UnixStream, buffer: &mut Vec<u8>) -> Result<(), Failure> {
    while buffer.is_empty() {
        if read_some(stream, buffer).await? == 0 {
            return Err(Failure::Authentication("closed"));
        }
    }
    if buffer.first() != Some(&0) {
        return Err(Failure::Authentication("no leading NUL byte"));
    }
    buffer.remove(0);
    loop {
        let line = read_line(stream, buffer).await?;
        let mut words = line.split(' ');
        let reply = match (words.next(), words.next()) {
            (Some("AUTH"), Some("EXTERNAL")) => match words.next() {
                Some(_) => OK,
                None => "DATA",
            },
            (Some("DATA"), _) => OK,
            (Some("NEGOTIATE_UNIX_FD"), None) => "AGREE_UNIX_FD",
            (Some("BEGIN"), None) => return Ok(()),
            (Some("AUTH" | "CANCEL" | "ERROR"), _) => "REJECTED EXTERNAL",
            _ => "ERROR",
        };
        write_all(stream, format!("{reply}\r\n").as_bytes()).await?;
    }
}

/// The next line of `buffer`, read from `stream` until it ends with CRLF.
async fn read_line(stream: &UnixStream, buffer: &mut Vec<u8>) -> Result<String, Failure> {
    loop {
        if let Some(end) = buffer.windows(2).position(|pair| pair == b"\r\n") {
            let line: Vec<u8> = buffer.drain(..end + 2).take(end).collect();
            return String::from_utf8(line).map_err(|_| Failure::Authentication("not UTF-8"));
        }
        if buffer.len() > MAX_LINE {
            return Err(Failure::Authentication("line too long"));
        }
        if read_some(stream, buffer).await? == 0 {
            return Err(Failure::Authentication("closed"));
        }
    }
}

/// Reads what is available onto `buffer`; 0 at the end.
async fn read_some(stream: &UnixStream, buffer: &mut Vec<u8>) -> io::Result<usize> {
    let mut chunk = [0; 4096];
    let read = stream
        .async_io(Interest::READABLE, || stream.try_read(&mut chunk))
        .await?;
    buffer.extend_from_slice(chunk.get(..read).unwrap_or_default());
    Ok(read)
}

async fn write_all(stream: &UnixStream, bytes: &[u8]) -> io::Result<()> {
    let mut written = 0;
    while written < bytes.len() {
        let rest = bytes.get(written..).unwrap_or_default();
        written += stream
            .async_io(Interest::WRITABLE, || stream.try_write(rest))
            .await?;
    }
    Ok(())
}

/// Once the other end of `released` is closed.
async fn closed(released: &UnixStream) {
    let mut chunk = [0; 64];
    loop {
        match released
            .async_io(Interest::READABLE, || released.try_read(&mut chunk))
            .await
        {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration as StdDuration;

    use libserviced::testing::FakeServiced;
    use rustix::net::RecvAncillaryBuffer;
    use rustix::net::RecvAncillaryMessage;
    use rustix::net::RecvFlags;
    use tokio::io::AsyncReadExt as _;
    use tokio::io::AsyncWriteExt as _;

    use super::*;

    /// kubelet's side of a connection.
    struct Kubelet {
        stream: UnixStream,
        buffer: Vec<u8>,
        serial: u32,
    }

    impl Kubelet {
        async fn line(&mut self, line: &str) -> String {
            self.stream.write_all(line.as_bytes()).await.unwrap();
            let mut reply = Vec::new();
            while !reply.ends_with(b"\r\n") {
                reply.push(self.stream.read_u8().await.unwrap());
            }
            String::from_utf8(reply).unwrap()
        }

        async fn call(&mut self, interface: &str, member: &str, body: Body, signature: &str) {
            self.serial += 1;
            let mut call = Message::new(Kind::MethodCall, self.serial);
            call.path = Some(LOGIND_PATH.into());
            call.interface = Some(interface.into());
            call.member = Some(member.into());
            call.signature = signature.into();
            call.body = body.into_bytes();
            self.stream.write_all(&call.encode()).await.unwrap();
        }

        async fn message(&mut self) -> Message {
            loop {
                if let Some((message, length)) = Message::parse(&self.buffer).unwrap() {
                    self.buffer.drain(..length);
                    return message;
                }
                let mut chunk = [0; 4096];
                let read =
                    tokio::time::timeout(StdDuration::from_secs(5), self.stream.read(&mut chunk))
                        .await
                        .expect("a message in time")
                        .unwrap();
                assert!(read > 0, "closed");
                self.buffer.extend_from_slice(&chunk[..read]);
            }
        }

        /// The reply to `Inhibit`, with the fd it carries.
        async fn inhibitor(&mut self) -> (Message, OwnedFd) {
            self.stream.readable().await.unwrap();
            let mut bytes = [0; 4096];
            let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(1))];
            let mut control = RecvAncillaryBuffer::new(&mut space);
            let received = rustix::net::recvmsg(
                &self.stream,
                &mut [io::IoSliceMut::new(&mut bytes)],
                &mut control,
                RecvFlags::CMSG_CLOEXEC,
            )
            .unwrap();
            let fd = control
                .drain()
                .find_map(|message| match message {
                    RecvAncillaryMessage::ScmRights(mut fds) => fds.next(),
                    _ => None,
                })
                .expect("an fd");
            self.buffer.extend_from_slice(&bytes[..received.bytes]);
            (self.message().await, fd)
        }
    }

    async fn wait_locks(fake: &FakeServiced, expected: &[u32]) {
        let mut locks = fake.shutdown_locks();
        tokio::time::timeout(
            StdDuration::from_secs(5),
            locks.wait_for(|held| held == expected),
        )
        .await
        .expect("the locks in time")
        .unwrap();
    }

    #[tokio::test]
    async fn kubelet_s_delay_lock_follows_serviced_s() {
        let dir = tempfile::tempdir().unwrap();
        let (fake, serviced) = FakeServiced::start(dir.path(), &dir.path().join("root")).await;
        let period = Duration::try_from("30s".to_owned()).unwrap();
        let (_grace_period, receiver) = watch::channel(Some(period));
        let logind = Arc::new(Logind::new(serviced, receiver));
        let (ours, theirs) = UnixStream::pair().unwrap();
        tokio::spawn(Arc::clone(&logind).connection(ours));
        let mut kubelet = Kubelet {
            stream: theirs,
            buffer: Vec::new(),
            serial: 0,
        };

        // godbus's exchange: the mechanisms, EXTERNAL with the uid in hexadecimal, unix fds.
        assert_eq!(kubelet.line("\0AUTH\r\n").await, "REJECTED EXTERNAL\r\n");
        assert!(
            kubelet
                .line("AUTH EXTERNAL 30\r\n")
                .await
                .starts_with("OK ")
        );
        assert_eq!(
            kubelet.line("NEGOTIATE_UNIX_FD\r\n").await,
            "AGREE_UNIX_FD\r\n"
        );
        kubelet.stream.write_all(b"BEGIN\r\n").await.unwrap();

        kubelet.call(BUS, "Hello", Body::default(), "").await;
        let hello = kubelet.message().await;
        assert_eq!(
            (hello.kind, hello.reply_serial),
            (Kind::MethodReturn, Some(1))
        );
        assert_eq!(hello.strings(1).unwrap(), [":1.1"]);

        let property = Body::default()
            .string(MANAGER)
            .string("InhibitDelayMaxUSec");
        kubelet.call(PROPERTIES, "Get", property, "ss").await;
        let delay = kubelet.message().await;
        assert_eq!(delay.signature, "v");
        assert_eq!(
            delay.body,
            Body::default().variant_u64(30_000_000).into_bytes()
        );
        let unknown = Body::default().string(MANAGER).string("BlockInhibited");
        kubelet.call(PROPERTIES, "Get", unknown, "ss").await;
        assert_eq!(kubelet.message().await.kind, Kind::Error);

        let inhibit = Body::default()
            .string("shutdown")
            .string("kubelet")
            .string("Kubelet needs time to handle node shutdown")
            .string("delay");
        kubelet.call(MANAGER, "Inhibit", inhibit, "ssss").await;
        let (reply, lock) = kubelet.inhibitor().await;
        assert_eq!((reply.signature.as_str(), reply.unix_fds), ("h", 1));
        wait_locks(&fake, &[35]).await;

        let rule = "type='signal',interface='org.freedesktop.login1.Manager',\
                    member='PrepareForShutdown',path='/org/freedesktop/login1'";
        kubelet
            .call(BUS, "AddMatch", Body::default().string(rule), "s")
            .await;
        assert_eq!(kubelet.message().await.kind, Kind::MethodReturn);
        kubelet
            .call(
                "org.freedesktop.systemd1.Manager",
                "KillUnit",
                Body::default(),
                "",
            )
            .await;
        assert_eq!(kubelet.message().await.kind, Kind::Error, "not logind's");

        fake.announce_shutdown();
        let signal = kubelet.message().await;
        assert_eq!(signal.kind, Kind::Signal);
        assert_eq!(signal.member.as_deref(), Some("PrepareForShutdown"));
        assert_eq!(signal.body, Body::default().boolean(true).into_bytes());

        drop(lock);
        wait_locks(&fake, &[]).await;
    }
}

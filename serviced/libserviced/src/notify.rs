//! The systemd notify protocol: datagrams such as `READY=1` or `STATUS=...` to the unix socket
//! `NOTIFY_SOCKET` names, which serviced gives every process of a service.

use std::env;
use std::io;
use std::os::unix::net::UnixDatagram;

/// The environment variable naming the notify socket.
pub const SOCKET_VARIABLE: &str = "NOTIFY_SOCKET";

/// Tells serviced the service is ready.
///
/// # Errors
///
/// When the datagram cannot be sent. Without `NOTIFY_SOCKET` (run outside serviced), nothing is
/// sent.
pub fn ready() -> io::Result<()> {
    send("READY=1")
}

/// Sets the service's status text, shown in its status.
///
/// # Errors
///
/// As [`ready`].
pub fn status(text: &str) -> io::Result<()> {
    send(&format!("STATUS={text}"))
}

/// Sends `message`, newline-separated `KEY=value` assignments, to `NOTIFY_SOCKET`.
fn send(message: &str) -> io::Result<()> {
    let Some(path) = env::var_os(SOCKET_VARIABLE) else {
        return Ok(());
    };
    let socket = UnixDatagram::unbound()?;
    socket.send_to(message.as_bytes(), path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sends_to_the_socket() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let path = dir.path().join("notify");
        let receiver = UnixDatagram::bind(&path).expect("a datagram socket");
        // SAFETY: this test is the only one in this crate touching NOTIFY_SOCKET.
        unsafe { env::set_var(SOCKET_VARIABLE, &path) };
        ready().expect("READY=1 sent");
        status("syncing").expect("STATUS sent");
        let mut buffer = [0; 64];
        let length = receiver.recv(&mut buffer).expect("a datagram");
        assert_eq!(&buffer[..length], b"READY=1");
        let length = receiver.recv(&mut buffer).expect("a datagram");
        assert_eq!(&buffer[..length], b"STATUS=syncing");
    }
}

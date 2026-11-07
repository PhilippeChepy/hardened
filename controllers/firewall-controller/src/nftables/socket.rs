//! A netfilter netlink socket (`AF_NETLINK`, `NETLINK_NETFILTER`), blocking with a timeout: the
//! controller's few requests are made on tokio's blocking threads.
//!
//! Only messages from the kernel (port 0) are read: another process could address our port.

use std::io;
use std::os::fd::OwnedFd;
use std::time::Duration;

use rustix::net::AddressFamily;
use rustix::net::RecvFlags;
use rustix::net::SendFlags;
use rustix::net::SocketFlags;
use rustix::net::SocketType;
use rustix::net::netlink;
use rustix::net::netlink::SocketAddrNetlink;
use rustix::net::sockopt;

use super::MessageKind;
use super::Messages;
use super::RuleInfo;
use super::attr::Attrs;
use crate::ruleset::Ruleset;

/// The receive buffer: dumps come in datagrams of up to 32 KiB.
const BUFFER_LEN: usize = 64 * 1024;
/// How long the kernel has to answer.
const TIMEOUT: Duration = Duration::from_secs(5);
/// `NLMSG_ERROR`, `NLMSG_DONE`.
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `ENOENT`.
const ENOENT: i32 = 2;

/// Why a request failed.
#[derive(Debug, thiserror::Error)]
pub enum NftError {
    /// The kernel has no nf_tables: no `NETLINK_NETFILTER` socket.
    #[error("the kernel has no nf_tables (NETLINK_NETFILTER): {0}")]
    Unavailable(io::Error),
    /// The socket failed, or the kernel did not answer in time.
    #[error("netlink: {0}")]
    Io(#[from] io::Error),
    /// The kernel refused a message.
    #[error("{what}: {error}")]
    Refused {
        /// What the message was.
        what: String,
        /// The kernel's errno.
        error: io::Error,
    },
}

impl From<rustix::io::Errno> for NftError {
    fn from(errno: rustix::io::Errno) -> Self {
        Self::Io(errno.into())
    }
}

/// A message of a datagram.
struct Message<'a> {
    kind: u16,
    sequence: u32,
    /// After the netlink header.
    payload: &'a [u8],
}

impl Message<'_> {
    /// The attributes of an nf_tables message (after its nfgenmsg).
    fn attrs(&self) -> Attrs<'_> {
        Attrs(self.payload.get(4..).unwrap_or_default())
    }

    /// The errno of an `NLMSG_ERROR`: 0 for an acknowledgment.
    fn error(&self) -> Option<i32> {
        let code = i32::from_ne_bytes(*self.payload.first_chunk::<4>()?);
        Some(code.saturating_neg())
    }
}

/// The messages of `datagram`, each 4-byte aligned; a truncated one ends it.
fn split(mut datagram: &[u8]) -> Vec<Message<'_>> {
    let mut messages = Vec::new();
    while let Some(header) = datagram.first_chunk::<16>() {
        let field = |range: std::ops::Range<usize>| &header[range];
        let len = u32::from_ne_bytes(field(0..4).try_into().unwrap_or_default());
        let Some(len) = usize::try_from(len).ok().filter(|&len| len >= 16) else {
            break;
        };
        let Some(message) = datagram.get(..len) else {
            break;
        };
        messages.push(Message {
            kind: u16::from_ne_bytes(field(4..6).try_into().unwrap_or_default()),
            sequence: u32::from_ne_bytes(field(8..12).try_into().unwrap_or_default()),
            payload: &message[16..],
        });
        datagram = datagram.get(len.next_multiple_of(4)..).unwrap_or_default();
    }
    messages
}

/// A netfilter netlink socket.
pub struct NftSocket {
    fd: OwnedFd,
    /// The sequence number of the next request.
    sequence: u32,
    buffer: Vec<u8>,
}

impl NftSocket {
    /// Opens a socket; [`NftError::Unavailable`] when the kernel has no nf_tables.
    pub fn open() -> Result<Self, NftError> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC,
            Some(netlink::NETFILTER),
        )
        .map_err(|error| NftError::Unavailable(error.into()))?;
        rustix::net::bind(&fd, &SocketAddrNetlink::new(0, 0))?;
        sockopt::set_socket_timeout(&fd, sockopt::Timeout::Recv, Some(TIMEOUT))?;
        // Numbered from the clock's seconds: replies to an earlier process's requests (the same
        // port, reused) are not taken for ours.
        let sequence = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(1, |now| now.as_secs() as u32);
        Ok(Self {
            fd,
            sequence,
            buffer: vec![0; BUFFER_LEN],
        })
    }

    /// Replaces the table by `ruleset`, or removes it (`None`), in one transaction. Returns the
    /// generation after it.
    pub fn apply(&mut self, ruleset: Option<&Ruleset>) -> Result<u32, NftError> {
        let batch = super::batch(ruleset, self.sequence);
        self.apply_batch(&batch)
    }

    /// The sequence number the next request should start from.
    #[must_use]
    pub fn next_sequence(&self) -> u32 {
        self.sequence
    }

    /// Sends `batch` (numbered from [`Self::next_sequence`]) and waits for its outcome: the
    /// first message the kernel refused, or the generation after it.
    pub fn apply_batch(&mut self, batch: &Messages) -> Result<u32, NftError> {
        self.sequence = batch.next_sequence();
        self.send(batch)?;
        // The batch's errors come before the generation's reply.
        let generation = super::get_generation(self.sequence);
        self.sequence = generation.next_sequence();
        self.send(&generation)?;
        let wanted = generation.sequences()[0];
        let mut refused = None;
        loop {
            let datagram = self.receive()?;
            for message in split(datagram) {
                if message.kind == NLMSG_ERROR && batch.sequences().contains(&message.sequence) {
                    let errno = message.error().unwrap_or(0);
                    if errno != 0 && refused.is_none() {
                        let what = batch.label_of(message.sequence).unwrap_or("the batch");
                        refused = Some(NftError::Refused {
                            what: what.to_owned(),
                            error: io::Error::from_raw_os_error(errno),
                        });
                    }
                    continue;
                }
                if message.sequence != wanted {
                    continue;
                }
                if let Some(error) = refused {
                    return Err(error);
                }
                return match message.kind {
                    kind if kind == MessageKind::NewGen.netlink_type() => {
                        Ok(super::parse_generation(message.attrs()).unwrap_or(0))
                    }
                    NLMSG_ERROR => Err(refusal("reading the generation", &message)),
                    _ => continue,
                };
            }
        }
    }

    /// The generation of nf_tables' rulesets.
    pub fn generation(&mut self) -> Result<u32, NftError> {
        let request = super::get_generation(self.sequence);
        self.sequence = request.next_sequence();
        let messages = self.request(&request, "reading the generation")?;
        Ok(messages
            .iter()
            .find_map(|attrs| super::parse_generation(Attrs(attrs)))
            .unwrap_or(0))
    }

    /// Whether the table exists.
    pub fn table_exists(&mut self) -> Result<bool, NftError> {
        let request = super::get_table(self.sequence);
        self.sequence = request.next_sequence();
        match self.request(&request, "reading the table") {
            Ok(_) => Ok(true),
            Err(NftError::Refused { error, .. }) if error.raw_os_error() == Some(ENOENT) => {
                Ok(false)
            }
            Err(error) => Err(error),
        }
    }

    /// The table's rules, in order (none without the table).
    pub fn rules(&mut self) -> Result<Vec<RuleInfo>, NftError> {
        let request = super::get_rules(self.sequence);
        self.sequence = request.next_sequence();
        let messages = match self.request(&request, "listing the rules") {
            Ok(messages) => messages,
            Err(NftError::Refused { error, .. }) if error.raw_os_error() == Some(ENOENT) => {
                return Ok(Vec::new());
            }
            Err(error) => return Err(error),
        };
        Ok(messages
            .iter()
            .filter_map(|attrs| RuleInfo::parse(Attrs(attrs)))
            .collect())
    }

    /// Sends the single request `request` and returns the attributes of the messages answering
    /// it, until its end: the reply of a request, `NLMSG_DONE` of a dump.
    fn request(&mut self, request: &Messages, what: &str) -> Result<Vec<Vec<u8>>, NftError> {
        self.send(request)?;
        let wanted = request.sequences()[0];
        let mut replies = Vec::new();
        loop {
            let datagram = self.receive()?;
            for message in split(datagram) {
                if message.sequence != wanted {
                    continue;
                }
                match message.kind {
                    NLMSG_ERROR if message.error() == Some(0) => return Ok(replies),
                    NLMSG_ERROR => return Err(refusal(what, &message)),
                    NLMSG_DONE => return Ok(replies),
                    _ => {
                        replies.push(message.attrs().0.to_vec());
                        // A request that is not a dump has one reply.
                        if !is_dump(request) {
                            return Ok(replies);
                        }
                    }
                }
            }
        }
    }

    fn send(&self, messages: &Messages) -> Result<(), NftError> {
        let kernel = SocketAddrNetlink::new(0, 0);
        rustix::net::sendto(&self.fd, messages.bytes(), SendFlags::empty(), &kernel)?;
        Ok(())
    }

    /// The next datagram from the kernel.
    fn receive(&mut self) -> Result<&[u8], NftError> {
        loop {
            let (_, len, sender) =
                rustix::net::recvfrom(&self.fd, &mut self.buffer[..], RecvFlags::TRUNC)
                    .map_err(io::Error::from)?;
            let from_kernel = sender
                .and_then(|sender| SocketAddrNetlink::try_from(sender).ok())
                .is_some_and(|sender| sender.pid() == 0);
            if !from_kernel {
                continue;
            }
            if len > BUFFER_LEN {
                return Err(NftError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("netlink datagram of {len} bytes, past {BUFFER_LEN}"),
                )));
            }
            return Ok(&self.buffer[..len]);
        }
    }
}

/// Whether `request` is a dump's.
fn is_dump(request: &Messages) -> bool {
    let flags = request
        .bytes()
        .get(6..8)
        .map_or(0, |b| u16::from_ne_bytes([b[0], b[1]]));
    flags & super::flags::DUMP == super::flags::DUMP
}

/// The error an `NLMSG_ERROR` answering `what` says.
fn refusal(what: &str, message: &Message<'_>) -> NftError {
    NftError::Refused {
        what: what.to_owned(),
        error: io::Error::from_raw_os_error(message.error().unwrap_or(0)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(kind: u16, sequence: u32, payload: &[u8]) -> Vec<u8> {
        let len = 16 + payload.len() as u32;
        let mut bytes = len.to_ne_bytes().to_vec();
        bytes.extend(kind.to_ne_bytes());
        bytes.extend(0u16.to_ne_bytes());
        bytes.extend(sequence.to_ne_bytes());
        bytes.extend(0u32.to_ne_bytes());
        bytes.extend(payload);
        bytes.resize(bytes.len().next_multiple_of(4), 0);
        bytes
    }

    #[test]
    fn splits_datagrams_and_reads_errors() {
        let mut datagram = message(NLMSG_ERROR, 7, &(-95i32).to_ne_bytes());
        datagram.extend(message(NLMSG_DONE, 8, &[0; 4]));
        datagram.extend(&[1, 2, 3]);
        let messages = split(&datagram);
        assert_eq!(messages.len(), 2);
        assert_eq!((messages[0].kind, messages[0].sequence), (NLMSG_ERROR, 7));
        assert_eq!(messages[0].error(), Some(95));
        assert_eq!(messages[1].kind, NLMSG_DONE);
        // A length past the datagram, or below a header's.
        assert!(split(&message(1, 1, &[0; 8])[..20]).is_empty());
        assert!(split(&[4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_empty());
    }

    #[test]
    fn requests_know_dumps() {
        assert!(is_dump(&crate::nftables::get_rules(1)));
        assert!(!is_dump(&crate::nftables::get_table(1)));
    }
}

//! A route netlink socket (`AF_NETLINK`, `NETLINK_ROUTE`) on tokio: requests with their
//! acknowledgment, dumps, and the notifications of multicast groups.
//!
//! Only messages from the kernel (port 0) are read: another process could address our port.

use std::io;
use std::os::fd::OwnedFd;

use netlink_packet_core::NLM_F_ACK;
use netlink_packet_core::NLM_F_DUMP;
use netlink_packet_core::NLM_F_REQUEST;
use netlink_packet_core::NetlinkHeader;
use netlink_packet_core::NetlinkMessage;
use netlink_packet_core::NetlinkPayload;
use netlink_packet_route::RouteNetlinkMessage;
use rustix::net::AddressFamily;
use rustix::net::RecvFlags;
use rustix::net::SendFlags;
use rustix::net::SocketFlags;
use rustix::net::SocketType;
use rustix::net::netlink::SocketAddrNetlink;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

/// `RTMGRP_LINK`: notifications of links appearing, changing and disappearing.
pub const RTMGRP_LINK: u32 = 1;

/// The receive buffer: dumps come in datagrams of up to 32 KiB.
const BUFFER_LEN: usize = 64 * 1024;

/// The netlink header's length, which a message's length includes.
const HEADER_LEN: usize = 16;

/// A route netlink socket.
pub struct NetlinkSocket {
    fd: AsyncFd<OwnedFd>,
    /// The sequence number of the last request.
    sequence: u32,
    buffer: Vec<u8>,
}

impl NetlinkSocket {
    /// Opens a socket, subscribed to the multicast `groups` (`RTMGRP_*`, 0 for none).
    ///
    /// # Panics
    ///
    /// Outside of a tokio runtime.
    pub fn open(groups: u32) -> io::Result<Self> {
        let fd = rustix::net::socket_with(
            AddressFamily::NETLINK,
            SocketType::RAW,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            // NETLINK_ROUTE.
            None,
        )?;
        rustix::net::bind(&fd, &SocketAddrNetlink::new(0, groups))?;
        // SAFETY: the `OwnedFd` keeps the socket open for as long as the `AsyncFd` owns it.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(Self {
            fd,
            sequence: 0,
            buffer: vec![0; BUFFER_LEN],
        })
    }

    /// Sends `message` and waits for the kernel's acknowledgment; with `NLM_F_DUMP` in `flags`,
    /// for the end of the dump instead. Returns the messages answering it.
    pub async fn request(
        &mut self,
        message: RouteNetlinkMessage,
        flags: u16,
    ) -> io::Result<Vec<RouteNetlinkMessage>> {
        // A dump ends with NLMSG_DONE, not an acknowledgment.
        let ack = if flags & NLM_F_DUMP == NLM_F_DUMP {
            0
        } else {
            NLM_F_ACK
        };
        self.sequence = self.sequence.wrapping_add(1);
        let sequence = self.sequence;
        let mut header = NetlinkHeader::default();
        header.flags = NLM_F_REQUEST | ack | flags;
        header.sequence_number = sequence;
        let mut packet = NetlinkMessage::new(header, NetlinkPayload::InnerMessage(message));
        packet.finalize();
        let mut buf = vec![0; packet.buffer_len()];
        packet.serialize(&mut buf);
        let kernel = SocketAddrNetlink::new(0, 0);
        self.fd
            .async_io(Interest::WRITABLE, |fd| {
                Ok(rustix::net::sendto(fd, &buf, SendFlags::empty(), &kernel)?)
            })
            .await?;

        let mut replies = Vec::new();
        loop {
            // Replies to an earlier request, abandoned by a cancelled caller, are skipped.
            for reply in self.receive().await? {
                if reply.header.sequence_number != sequence {
                    continue;
                }
                match reply.payload {
                    NetlinkPayload::InnerMessage(message) => replies.push(message),
                    NetlinkPayload::Error(error) => {
                        return match error.code {
                            None => Ok(replies),
                            Some(_) => Err(error.to_io()),
                        };
                    }
                    NetlinkPayload::Done(done) if done.code < 0 => {
                        return Err(io::Error::from_raw_os_error(done.code.saturating_neg()));
                    }
                    NetlinkPayload::Done(_) => return Ok(replies),
                    _ => {}
                }
            }
        }
    }

    /// The next notifications of the subscribed groups. Fails with `ENOBUFS` when the kernel
    /// dropped some, the socket's buffer being full.
    pub async fn notifications(&mut self) -> io::Result<Vec<RouteNetlinkMessage>> {
        loop {
            let messages: Vec<_> = self
                .receive()
                .await?
                .into_iter()
                .filter_map(|message| match message.payload {
                    NetlinkPayload::InnerMessage(message) => Some(message),
                    _ => None,
                })
                .collect();
            if !messages.is_empty() {
                return Ok(messages);
            }
        }
    }

    /// The messages of the next datagram from the kernel, but those that do not decode.
    async fn receive(&mut self) -> io::Result<Vec<NetlinkMessage<RouteNetlinkMessage>>> {
        loop {
            let buffer = &mut self.buffer;
            let (len, sender) = self
                .fd
                .async_io(Interest::READABLE, |fd| {
                    let (_, len, sender) =
                        rustix::net::recvfrom(fd, &mut buffer[..], RecvFlags::TRUNC)?;
                    Ok((len, sender))
                })
                .await?;
            let from_kernel = sender
                .and_then(|sender| SocketAddrNetlink::try_from(sender).ok())
                .is_some_and(|sender| sender.pid() == 0);
            if !from_kernel {
                continue;
            }
            let datagram = self.buffer.get(..len).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("netlink datagram of {len} bytes, past {BUFFER_LEN}"),
                )
            })?;
            return Ok(split(datagram)
                .filter_map(|bytes| match NetlinkMessage::deserialize(bytes) {
                    Ok(message) => Some(message),
                    Err(error) => {
                        tracing::debug!("skipping an undecodable netlink message: {error}");
                        None
                    }
                })
                .collect());
        }
    }
}

/// The messages of a datagram, each 4-byte aligned; a truncated one ends it.
fn split(mut datagram: &[u8]) -> impl Iterator<Item = &[u8]> {
    std::iter::from_fn(move || {
        let len = u32::from_ne_bytes(*datagram.first_chunk::<4>()?);
        let len = usize::try_from(len).ok().filter(|&len| len >= HEADER_LEN)?;
        let message = datagram.get(..len)?;
        datagram = datagram.get(len.next_multiple_of(4)..).unwrap_or_default();
        Some(message)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A message of `len` bytes, its length in its header.
    fn message(len: u32, fill: u8) -> Vec<u8> {
        let mut message = len.to_ne_bytes().to_vec();
        message.resize(len as usize, fill);
        message
    }

    #[test]
    fn splits_datagrams() {
        let mut datagram = message(20, 1);
        datagram.extend(message(18, 2));
        datagram.extend([0, 0]);
        datagram.extend(message(16, 3));
        let messages: Vec<&[u8]> = split(&datagram).collect();
        assert_eq!(
            messages,
            [&datagram[..20], &datagram[20..38], &datagram[40..]]
        );

        // Truncated, or of a length shorter than its header.
        for bad in [&message(20, 1)[..19], &message(8, 1), &[1, 2]] {
            assert_eq!(split(bad).count(), 0, "{bad:?}");
        }
        assert_eq!(split(&message(18, 1)).count(), 1, "unaligned last message");
    }
}

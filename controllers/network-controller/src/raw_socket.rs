//! Link-layer DHCP transport, for interfaces without an IPv4 address yet.
//!
//! A UDP socket is not enough before the interface has an address: Linux drops the servers'
//! replies when reverse path filtering is on (hardened enables it, and a reply's source cannot be
//! validated without an address or route), and it picks another interface's address as the
//! source of our broadcasts instead of `0.0.0.0`. Like other DHCP clients, network-controller then
//! exchanges whole IPv4 packets on an `AF_PACKET` socket, only while acquiring a lease: without a
//! socket filter it receives every IPv4 packet of the interface.

use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::os::fd::OwnedFd;
use std::ptr;

use rustix::net::AddressFamily;
use rustix::net::RecvFlags;
use rustix::net::SendFlags;
use rustix::net::SocketFlags;
use rustix::net::SocketType;
use rustix::net::addr::SocketAddrArg;
use rustix::net::addr::SocketAddrLen;
use rustix::net::addr::SocketAddrOpaque;
use rustix::net::eth;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;

use crate::dhcp::CLIENT_PORT;
use crate::dhcp::Transport;

const ETH_P_IP: u16 = 0x0800;
const IPPROTO_UDP: u8 = 17;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

/// An `AF_PACKET` datagram socket carrying the IPv4 packets of one interface.
pub struct RawSocket {
    fd: AsyncFd<OwnedFd>,
    ifindex: u32,
}

impl RawSocket {
    /// Opens the socket of the interface `ifindex`.
    ///
    /// # Panics
    ///
    /// Outside of a tokio runtime.
    pub fn open(ifindex: u32) -> io::Result<Self> {
        let fd = rustix::net::socket_with(
            AddressFamily::PACKET,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
            Some(eth::IP),
        )?;
        rustix::net::bind(&fd, &LinkAddr::new(ifindex, None))?;
        // SAFETY: the `OwnedFd` keeps the socket open for as long as the `AsyncFd` owns it.
        let fd = unsafe { AsyncFd::register(fd) }?;
        Ok(Self { fd, ifindex })
    }
}

impl Transport for RawSocket {
    /// Sends `payload` from `0.0.0.0:68` to `target`, which must be the limited broadcast address
    /// (we know no unicast link-layer address).
    async fn send_to(&self, payload: &[u8], target: SocketAddrV4) -> io::Result<()> {
        if !target.ip().is_broadcast() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("cannot send to {target} without an address"),
            ));
        }
        let packet = udp_packet(
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT),
            target,
            payload,
        );
        let destination = LinkAddr::new(self.ifindex, Some([0xff; 6]));
        self.fd
            .async_io(Interest::WRITABLE, |fd| {
                Ok(rustix::net::sendto(
                    fd,
                    &packet,
                    SendFlags::empty(),
                    &destination,
                )?)
            })
            .await
            .map(drop)
    }

    /// Receives the payload of the next UDP datagram to port 68, skipping other packets.
    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut packet = vec![0u8; usize::from(u16::MAX)];
        loop {
            let len = self
                .fd
                .async_io(Interest::READABLE, |fd| {
                    Ok(rustix::net::recvfrom(fd, &mut packet[..], RecvFlags::empty())?.0)
                })
                .await?;
            if let Some(datagram) = parse_udp(&packet[..len], CLIENT_PORT) {
                let len = datagram.payload.len().min(buf.len());
                buf[..len].copy_from_slice(&datagram.payload[..len]);
                return Ok((len, datagram.source.into()));
            }
        }
    }
}

/// `struct sockaddr_ll` (`<linux/if_packet.h>`).
#[repr(C)]
struct LinkAddr {
    family: u16,
    /// Big-endian.
    protocol: u16,
    ifindex: i32,
    hatype: u16,
    pkttype: u8,
    halen: u8,
    addr: [u8; 8],
}

impl LinkAddr {
    /// IPv4 on `ifindex`, to the Ethernet address `mac` when sending.
    #[must_use]
    fn new(ifindex: u32, mac: Option<[u8; 6]>) -> Self {
        let mut addr = [0; 8];
        if let Some(mac) = mac {
            addr[..6].copy_from_slice(&mac);
        }
        Self {
            family: AddressFamily::PACKET.as_raw(),
            protocol: ETH_P_IP.to_be(),
            ifindex: ifindex.try_into().unwrap_or(i32::MAX),
            hatype: 0,
            pkttype: 0,
            halen: if mac.is_some() { 6 } else { 0 },
            addr,
        }
    }
}

// SAFETY: `with_sockaddr` passes a pointer to `self`, a `#[repr(C)]` mirror of `sockaddr_ll`,
// valid for its size while `f` runs.
unsafe impl SocketAddrArg for LinkAddr {
    unsafe fn with_sockaddr<R>(
        &self,
        f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R,
    ) -> R {
        f(
            ptr::from_ref(self).cast(),
            size_of::<Self>() as SocketAddrLen,
        )
    }
}

/// An IPv4 packet carrying `payload` in a UDP datagram, checksums included.
#[must_use]
fn udp_packet(source: SocketAddrV4, destination: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
    let udp_len = UDP_HEADER_LEN + payload.len();
    let total_len = IPV4_HEADER_LEN + udp_len;
    let mut packet = Vec::with_capacity(total_len);
    // IPv4 header: version 4, 5 words, no options, not fragmented, TTL 64.
    packet.extend_from_slice(&[0x45, 0]);
    packet.extend_from_slice(&(total_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0, 0, 0, 64, IPPROTO_UDP, 0, 0]);
    packet.extend_from_slice(&source.ip().octets());
    packet.extend_from_slice(&destination.ip().octets());
    let header_checksum = checksum(&[&packet]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    let udp_start = packet.len();
    packet.extend_from_slice(&source.port().to_be_bytes());
    packet.extend_from_slice(&destination.port().to_be_bytes());
    packet.extend_from_slice(&(udp_len as u16).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(payload);
    let mut pseudo_header = [0u8; 12];
    pseudo_header[..4].copy_from_slice(&source.ip().octets());
    pseudo_header[4..8].copy_from_slice(&destination.ip().octets());
    pseudo_header[9] = IPPROTO_UDP;
    pseudo_header[10..].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // An all-zero UDP checksum means "none" (RFC 768).
    let udp_checksum = match checksum(&[&pseudo_header, &packet[udp_start..]]) {
        0 => 0xffff,
        sum => sum,
    };
    packet[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());
    packet
}

/// A UDP datagram received in an IPv4 packet.
#[derive(Debug, PartialEq, Eq)]
struct Datagram<'packet> {
    /// Its sender.
    source: SocketAddrV4,
    /// What it carries.
    payload: &'packet [u8],
}

/// The datagram in `packet` if it is an unfragmented IPv4 UDP datagram to `port`. Checksums are
/// not verified: packet sockets may see packets before checksum offload fills them.
#[must_use]
fn parse_udp(packet: &[u8], port: u16) -> Option<Datagram<'_>> {
    let header_len = usize::from(packet.first()? & 0x0f) * 4;
    if packet[0] >> 4 != 4
        || header_len < IPV4_HEADER_LEN
        || packet.len() < header_len + UDP_HEADER_LEN
    {
        return None;
    }
    let be16 = |bytes: &[u8], at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    let more_fragments_or_offset = be16(packet, 6) & 0x3fff;
    if packet[9] != IPPROTO_UDP || more_fragments_or_offset != 0 {
        return None;
    }
    // The total length excludes the link layer's padding.
    let packet = packet
        .get(..usize::from(be16(packet, 2)))
        .filter(|p| p.len() >= header_len + UDP_HEADER_LEN)?;
    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let udp = packet.get(header_len..)?;
    if udp.len() < UDP_HEADER_LEN || be16(udp, 2) != port {
        return None;
    }
    let payload = udp.get(UDP_HEADER_LEN..usize::from(be16(udp, 4)))?;
    Some(Datagram {
        source: SocketAddrV4::new(source, be16(udp, 0)),
        payload,
    })
}

/// Internet checksum (RFC 1071) of the concatenation of `chunks`, each of even length but the
/// last.
#[must_use]
fn checksum(chunks: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in chunks {
        let mut words = chunk.chunks_exact(2);
        for word in &mut words {
            sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
        }
        if let [last] = words.remainder() {
            sum += u32::from(*last) << 8;
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, CLIENT_PORT);
    const BROADCAST: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::BROADCAST, 67);

    #[test]
    fn builds_valid_packets() {
        let packet = udp_packet(CLIENT, BROADCAST, b"hello");
        assert_eq!(packet.len(), 20 + 8 + 5);
        assert_eq!(checksum(&[&packet[..20]]), 0, "IPv4 header checksum");
        let mut pseudo = vec![0, 0, 0, 0, 255, 255, 255, 255, 0, IPPROTO_UDP, 0, 13];
        pseudo.extend_from_slice(&packet[20..]);
        assert_eq!(checksum(&[&pseudo]), 0, "UDP checksum");
    }

    #[test]
    fn checksum_matches_rfc1071_example() {
        assert_eq!(
            checksum(&[&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]]),
            !0xddf2
        );
        assert_eq!(
            checksum(&[&[0x00, 0x01], &[0xf2]]),
            !0xf201,
            "odd length pads with zero"
        );
    }

    #[test]
    fn parses_udp() {
        let server = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 67);
        let mut packet = udp_packet(
            server,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, CLIENT_PORT),
            b"offer",
        );
        // Ethernet padding past the IPv4 total length.
        packet.extend_from_slice(&[0; 10]);
        assert_eq!(
            parse_udp(&packet, CLIENT_PORT),
            Some(Datagram {
                source: server,
                payload: b"offer"
            })
        );
        assert_eq!(parse_udp(&packet, 67), None, "other port");
        // Our own DISCOVER, seen as outgoing.
        assert_eq!(
            parse_udp(&udp_packet(CLIENT, BROADCAST, b"x"), CLIENT_PORT),
            None
        );

        let mut fragment = packet.clone();
        fragment[6] = 0x20; // more fragments
        assert_eq!(parse_udp(&fragment, CLIENT_PORT), None);
        let mut tcp = packet.clone();
        tcp[9] = 6;
        assert_eq!(parse_udp(&tcp, CLIENT_PORT), None);
        assert_eq!(parse_udp(&packet[..25], CLIENT_PORT), None, "truncated");
        assert_eq!(parse_udp(&[], CLIENT_PORT), None);
    }
}

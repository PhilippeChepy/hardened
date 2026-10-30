//! DHCPv4 messages (RFC 2131 §2): the 236-byte BOOTP header, the magic cookie, then the options.
//! Server names and boot files (`sname`, `file`) are neither sent nor read, nor are options
//! overloaded into them.

use std::net::Ipv4Addr;

use crate::dhcp_option::DhcpOptions;

/// The bytes between the header and the options (RFC 2131 §3).
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

/// `htype` of Ethernet.
const ETHERNET: u8 = 1;
/// `hlen` of Ethernet.
const ETHERNET_ADDRESS_LEN: u8 = 6;
/// The flag asking servers to broadcast their replies.
const BROADCAST: u16 = 0x8000;
/// The lengths of `sname` and `file`, zeros when sent and ignored when received.
const SNAME_AND_FILE_LEN: usize = 64 + 128;

/// Why a datagram is not a DHCP message.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("truncated message")]
    Truncated,
    #[error("unknown opcode {0}")]
    Opcode(u8),
    #[error("no DHCP magic cookie")]
    MagicCookie,
    #[error("option {0} runs past the end of the message")]
    OptionOverrun(u8),
}

/// Whether a message goes to a server or comes from one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Opcode {
    BootRequest = 1,
    BootReply = 2,
}

/// A DHCP message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub opcode: Opcode,
    /// The transaction ID.
    pub xid: u32,
    /// Seconds since the client began acquiring or renewing.
    pub secs: u16,
    /// Asks for broadcast replies.
    pub broadcast: bool,
    /// The client's address, when it has one.
    pub ciaddr: Ipv4Addr,
    /// The address offered or leased to the client.
    pub yiaddr: Ipv4Addr,
    /// The next server to use in bootstrap.
    pub siaddr: Ipv4Addr,
    /// The relay agent's address.
    pub giaddr: Ipv4Addr,
    /// The client's hardware address, padded with zeros.
    pub chaddr: [u8; 16],
    pub options: DhcpOptions,
}

impl Message {
    /// A message of the Ethernet address `mac`, every other field zero.
    #[must_use]
    pub fn new(opcode: Opcode, xid: u32, mac: [u8; 6]) -> Self {
        let mut chaddr = [0; 16];
        chaddr[..6].copy_from_slice(&mac);
        Self {
            opcode,
            xid,
            secs: 0,
            broadcast: false,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            options: DhcpOptions::default(),
        }
    }

    /// The message in wire format.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(300);
        buf.extend_from_slice(&[self.opcode as u8, ETHERNET, ETHERNET_ADDRESS_LEN, 0]);
        buf.extend_from_slice(&self.xid.to_be_bytes());
        buf.extend_from_slice(&self.secs.to_be_bytes());
        let flags = if self.broadcast { BROADCAST } else { 0 };
        buf.extend_from_slice(&flags.to_be_bytes());
        for address in [self.ciaddr, self.yiaddr, self.siaddr, self.giaddr] {
            buf.extend_from_slice(&address.octets());
        }
        buf.extend_from_slice(&self.chaddr);
        buf.resize(buf.len() + SNAME_AND_FILE_LEN, 0);
        buf.extend_from_slice(&MAGIC_COOKIE);
        self.options.encode(&mut buf);
        buf
    }

    /// Decodes a message, checking its structure only: what it means is up to the caller.
    pub fn decode(buf: &[u8]) -> Result<Self, DecodeError> {
        let mut reader = Reader(buf);
        let [opcode, _htype, _hlen, _hops] = reader.take()?;
        let opcode = match opcode {
            1 => Opcode::BootRequest,
            2 => Opcode::BootReply,
            other => return Err(DecodeError::Opcode(other)),
        };
        let xid = u32::from_be_bytes(reader.take()?);
        let secs = u16::from_be_bytes(reader.take()?);
        let flags = u16::from_be_bytes(reader.take()?);
        let mut address = || reader.take::<4>().map(Ipv4Addr::from);
        let (ciaddr, yiaddr, siaddr, giaddr) = (address()?, address()?, address()?, address()?);
        let chaddr = reader.take()?;
        reader.take::<SNAME_AND_FILE_LEN>()?;
        if reader.take()? != MAGIC_COOKIE {
            return Err(DecodeError::MagicCookie);
        }
        Ok(Self {
            opcode,
            xid,
            secs,
            broadcast: flags & BROADCAST != 0,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            options: DhcpOptions::decode(reader.0)?,
        })
    }
}

/// Reads a buffer from its start.
struct Reader<'buf>(&'buf [u8]);

impl Reader<'_> {
    /// The next `N` bytes.
    fn take<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (bytes, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(DecodeError::Truncated)?;
        self.0 = rest;
        Ok(*bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dhcp_option::DhcpOption;
    use crate::dhcp_option::MessageType;

    /// The offset of the options.
    const OPTIONS: usize = 240;

    fn reply() -> Message {
        let mut msg = Message::new(Opcode::BootReply, 0x0102_0304, [2, 0, 0, 0, 0, 1]);
        msg.secs = 7;
        msg.broadcast = true;
        msg.ciaddr = [10, 0, 0, 9].into();
        msg.yiaddr = [10, 0, 0, 5].into();
        msg.siaddr = [10, 0, 0, 1].into();
        msg.giaddr = [10, 0, 0, 254].into();
        msg.options
            .insert(DhcpOption::MessageType(MessageType::Offer));
        msg
    }

    #[test]
    fn encodes_the_header() {
        let buf = reply().encode();
        assert_eq!(buf.len(), OPTIONS + 4);
        assert_eq!(&buf[..12], &[2, 1, 6, 0, 1, 2, 3, 4, 0, 7, 0x80, 0]);
        assert_eq!(
            &buf[12..28],
            &[10, 0, 0, 9, 10, 0, 0, 5, 10, 0, 0, 1, 10, 0, 0, 254]
        );
        assert_eq!(
            &buf[28..44],
            &[2, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(buf[44..236].iter().all(|&b| b == 0), "sname and file");
        assert_eq!(&buf[236..OPTIONS], &MAGIC_COOKIE);
        assert_eq!(&buf[OPTIONS..], &[53, 1, 2, 255]);
    }

    #[test]
    fn round_trips() {
        let msg = reply();
        assert_eq!(Message::decode(&msg.encode()), Ok(msg));
    }

    #[test]
    fn rejects_malformed_messages() {
        let valid = reply().encode();
        for len in [0, 1, 100, 235, 236, 239] {
            assert_eq!(
                Message::decode(&valid[..len]),
                Err(DecodeError::Truncated),
                "{len} bytes"
            );
        }
        let mut opcode = valid.clone();
        opcode[0] = 3;
        assert_eq!(Message::decode(&opcode), Err(DecodeError::Opcode(3)));
        let mut cookie = valid.clone();
        cookie[239] = 0;
        assert_eq!(Message::decode(&cookie), Err(DecodeError::MagicCookie));
        let mut overrun = valid[..OPTIONS].to_vec();
        overrun.extend_from_slice(&[53, 9, 2]);
        assert_eq!(
            Message::decode(&overrun),
            Err(DecodeError::OptionOverrun(53))
        );
    }

    #[test]
    fn ignores_what_follows_the_end_option() {
        let mut buf = reply().encode();
        // Padding, as the client sends, and garbage after the end option.
        buf.extend_from_slice(&[0, 0, 53, 1, 5, 1, 200]);
        let msg = Message::decode(&buf).unwrap();
        assert_eq!(msg.options.message_type(), Some(MessageType::Offer));
    }
}

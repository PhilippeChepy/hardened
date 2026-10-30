//! SNTP (RFC 4330, the client side of RFC 5905): a mode 3 request, the server's mode 4 reply.
//!
//! The request's transmit timestamp is a random cookie rather than the time: the server copies
//! it into its reply's origin timestamp, so a reply that does not echo it is not an answer to
//! this request (off-path spoofing must guess 64 bits). The send and receive times are kept
//! locally.

use std::net::Ipv4Addr;
use std::time::Duration;

/// The NTP port.
pub const PORT: u16 = 123;
/// The length of a packet without extensions.
const LEN: usize = 48;
/// Seconds from the NTP epoch (1900) to the Unix epoch (1970).
const UNIX_EPOCH: i64 = 2_208_988_800;
/// Replies further than this from their reference clock are not used (RFC 5905's MAXDIST
/// is 1 s; some leeway for SNTP servers).
const MAX_ROOT_DISTANCE: Duration = Duration::from_millis(1500);

/// A time as nanoseconds since the Unix epoch.
pub type Nanos = i64;

/// A request, with `cookie` as its transmit timestamp.
#[must_use]
pub fn request(cookie: [u8; 8]) -> [u8; LEN] {
    let mut packet = [0; LEN];
    // Leap indicator 0, version 4, mode 3 (client).
    packet[0] = (4 << 3) | 3;
    packet[40..48].copy_from_slice(&cookie);
    packet
}

/// A server's reply, checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reply {
    /// The server's distance to a reference clock, in servers: 1 for a reference clock's own.
    pub stratum: u8,
    /// The server's reference: a 4-character code at stratum 1, an IPv4 address (or a hash of an
    /// IPv6 address) above.
    pub reference: [u8; 4],
    /// The round trip from the server to its reference clock.
    pub root_delay: Duration,
    /// The server's error bound relative to its reference clock.
    pub root_dispersion: Duration,
    /// When the server received the request.
    pub receive: Nanos,
    /// When the server sent the reply.
    pub transmit: Nanos,
}

/// Why a datagram is not a usable reply.
#[must_use]
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Rejected {
    #[error("the reply is {0} bytes, shorter than {LEN}")]
    Short(usize),
    #[error("not a server reply (mode {0})")]
    NotServer(u8),
    #[error("the reply does not answer the request")]
    Unexpected,
    /// A kiss-o'-death (stratum 0): `RATE` (poll less often), `DENY` or `RSTR` (go away)...
    #[error("the server sent a kiss-o'-death: {}", String::from_utf8_lossy(.0))]
    Kiss([u8; 4]),
    #[error("the server is not synchronized")]
    Unsynchronized,
    #[error("the server is {0:?} from its reference clock")]
    TooFar(Duration),
    #[error("the reply has no timestamps")]
    NoTimestamps,
}

impl Reply {
    /// Checks `packet` answers the request sent with `cookie`.
    pub fn parse(packet: &[u8], cookie: [u8; 8]) -> Result<Self, Rejected> {
        let Some(packet) = packet.first_chunk::<LEN>() else {
            return Err(Rejected::Short(packet.len()));
        };
        let mode = packet[0] & 0b111;
        if mode != 4 {
            return Err(Rejected::NotServer(mode));
        }
        if packet[24..32] != cookie {
            return Err(Rejected::Unexpected);
        }
        let leap = packet[0] >> 6;
        let stratum = packet[1];
        let reference = packet[12..16].try_into().expect("4 bytes");
        if stratum == 0 {
            return Err(Rejected::Kiss(reference));
        }
        if leap == 3 || stratum >= 16 {
            return Err(Rejected::Unsynchronized);
        }
        // NTP short format: 16.16 fixed-point seconds.
        let short = |at: usize| {
            let value = u32::from_be_bytes(packet[at..at + 4].try_into().expect("4 bytes"));
            Duration::from_nanos((u64::from(value) * 1_000_000_000) >> 16)
        };
        let timestamp =
            |at: usize| u64::from_be_bytes(packet[at..at + 8].try_into().expect("8 bytes"));
        let (receive, transmit) = (timestamp(32), timestamp(40));
        let reply = Self {
            stratum,
            reference,
            root_delay: short(4),
            root_dispersion: short(8),
            receive: to_unix(receive),
            transmit: to_unix(transmit),
        };
        let distance = reply.root_distance();
        if distance > MAX_ROOT_DISTANCE {
            return Err(Rejected::TooFar(distance));
        }
        if receive == 0 || transmit == 0 {
            return Err(Rejected::NoTimestamps);
        }
        Ok(reply)
    }

    /// The server's distance to its reference clock.
    #[must_use]
    pub fn root_distance(&self) -> Duration {
        self.root_delay / 2 + self.root_dispersion
    }

    /// The reference, as text: the code of a stratum 1 server, the address of its server above.
    #[must_use]
    pub fn reference_id(&self) -> String {
        if self.stratum == 1 {
            self.reference
                .iter()
                .take_while(|&&b| b != 0)
                .map(|&b| {
                    if b.is_ascii_graphic() {
                        char::from(b)
                    } else {
                        '?'
                    }
                })
                .collect()
        } else {
            Ipv4Addr::from(self.reference).to_string()
        }
    }
}

/// An NTP timestamp as Unix nanoseconds. Its 32-bit seconds wrap every 136 years: those with
/// the high bit set are in era 0 (1968-2036), the others in era 1 (2036-2104).
#[must_use]
fn to_unix(timestamp: u64) -> Nanos {
    let seconds = (timestamp >> 32) as i64;
    let seconds = if seconds & 0x8000_0000 != 0 {
        seconds
    } else {
        seconds + (1 << 32)
    };
    let fraction = ((timestamp & 0xffff_ffff) * 1_000_000_000) >> 32;
    (seconds - UNIX_EPOCH) * 1_000_000_000 + fraction as i64
}

/// A measurement of the local clock against a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sample {
    /// What to add to the local clock to get the server's time.
    pub offset: Nanos,
    /// The round trip, less the server's processing time.
    pub delay: Duration,
}

impl Sample {
    /// From the local times the request was `sent` and the reply `received`.
    #[must_use]
    pub fn new(reply: &Reply, sent: Nanos, received: Nanos) -> Self {
        let offset = ((reply.receive - sent) + (reply.transmit - received)) / 2;
        let delay = (received - sent) - (reply.transmit - reply.receive);
        Self {
            offset,
            delay: Duration::from_nanos(delay.try_into().unwrap_or(0)),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const COOKIE: [u8; 8] = [1, 2, 3, 4, 5, 6, 7, 8];

    /// 2026-01-01T00:00:00Z.
    const NEW_YEAR: Nanos = 1_767_225_600_000_000_000;

    pub fn timestamp(unix: Nanos) -> [u8; 8] {
        let seconds = (unix.div_euclid(1_000_000_000) + UNIX_EPOCH) as u64 & 0xffff_ffff;
        let fraction = ((unix.rem_euclid(1_000_000_000) as u64) << 32) / 1_000_000_000;
        ((seconds << 32) | fraction).to_be_bytes()
    }

    fn reply(stratum: u8, receive: Nanos, transmit: Nanos) -> [u8; LEN] {
        let mut packet = [0; LEN];
        packet[0] = (4 << 3) | 4;
        packet[1] = stratum;
        packet[4..8].copy_from_slice(&0x0000_0800u32.to_be_bytes()); // root delay 1/32 s
        packet[8..12].copy_from_slice(&0x0000_0400u32.to_be_bytes()); // root dispersion 1/64 s
        packet[12..16].copy_from_slice(b"GPS\0");
        packet[24..32].copy_from_slice(&COOKIE);
        packet[32..40].copy_from_slice(&timestamp(receive));
        packet[40..48].copy_from_slice(&timestamp(transmit));
        packet
    }

    #[test]
    fn requests_carry_the_cookie() {
        let packet = request(COOKIE);
        assert_eq!(packet[0], 0x23);
        assert_eq!(packet[40..48], COOKIE);
        assert!(packet[1..40].iter().all(|&b| b == 0));
    }

    #[test]
    fn parses_replies() {
        let packet = reply(1, NEW_YEAR, NEW_YEAR + 1_000);
        let reply = Reply::parse(&packet, COOKIE).unwrap();
        assert_eq!(reply.stratum, 1);
        assert_eq!(reply.reference_id(), "GPS");
        assert_eq!(reply.root_delay, Duration::from_micros(31_250));
        assert_eq!(reply.root_dispersion, Duration::from_micros(15_625));
        // The 32-bit fraction is precise to the nanosecond, within rounding.
        assert!((reply.receive - NEW_YEAR).abs() <= 1);
        assert!((reply.transmit - NEW_YEAR - 1_000).abs() <= 1);
    }

    #[test]
    fn handles_the_2036_rollover() {
        // 2036-02-07T06:28:16Z is NTP second 2^32, second 0 of era 1.
        let rollover: Nanos = 2_085_978_496_000_000_000;
        let packet = reply(2, rollover + 5_000_000_000, rollover + 5_000_000_000);
        let reply = Reply::parse(&packet, COOKIE).unwrap();
        assert_eq!(reply.receive, rollover + 5_000_000_000);
    }

    #[test]
    fn rejects_bad_replies() {
        let good = reply(2, NEW_YEAR, NEW_YEAR);
        assert_eq!(Reply::parse(&good[..47], COOKIE), Err(Rejected::Short(47)));
        assert_eq!(Reply::parse(&good, [0; 8]), Err(Rejected::Unexpected));

        let mut client = good;
        client[0] = (4 << 3) | 3;
        assert_eq!(Reply::parse(&client, COOKIE), Err(Rejected::NotServer(3)));

        let mut kiss = reply(0, NEW_YEAR, NEW_YEAR);
        kiss[12..16].copy_from_slice(b"RATE");
        assert_eq!(Reply::parse(&kiss, COOKIE), Err(Rejected::Kiss(*b"RATE")));

        let mut alarm = good;
        alarm[0] |= 3 << 6;
        assert_eq!(Reply::parse(&alarm, COOKIE), Err(Rejected::Unsynchronized));
        assert_eq!(
            Reply::parse(&reply(16, NEW_YEAR, NEW_YEAR), COOKIE),
            Err(Rejected::Unsynchronized)
        );

        let mut far = good;
        far[8..12].copy_from_slice(&0x0002_0000u32.to_be_bytes()); // 2 s
        assert!(matches!(
            Reply::parse(&far, COOKIE),
            Err(Rejected::TooFar(_))
        ));

        let mut empty = good;
        empty[40..48].fill(0);
        assert_eq!(Reply::parse(&empty, COOKIE), Err(Rejected::NoTimestamps));
    }

    #[test]
    fn computes_offset_and_delay() {
        // The local clock is 2 s behind; 10 ms each way; the server takes 1 ms.
        let server = |local: Nanos| local + 2_000_000_000;
        let sent = NEW_YEAR;
        let receive = server(sent + 10_000_000);
        let transmit = receive + 1_000_000;
        let received = sent + 21_000_000;
        let reply = Reply {
            stratum: 2,
            reference: [0; 4],
            root_delay: Duration::ZERO,
            root_dispersion: Duration::ZERO,
            receive,
            transmit,
        };
        assert_eq!(
            Sample::new(&reply, sent, received),
            Sample {
                offset: 2_000_000_000,
                delay: Duration::from_millis(20)
            }
        );
    }
}

//! What the firewall blocked, from the kernel's log: the lines of the table's `log` rules
//! (`/dev/kmsg` records, Linux's `nf_log_syslog` format after the prefix), each kind of packet
//! counted once, the most recent first.

use std::net::IpAddr;
use std::time::Duration;
use std::time::SystemTime;

use crate::ruleset::LOG_PREFIX_IN;
use crate::ruleset::LOG_PREFIX_OUT;

/// A packet a log rule logged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoggedPacket {
    /// Since boot, as the kernel's log times its records.
    pub since_boot: Duration,
    /// What the packet was.
    pub key: PacketKind,
}

/// What a logged packet was, which the recent ones are grouped by.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PacketKind {
    /// Blocked by the output chain.
    pub outbound: bool,
    /// The interface it came in on, or was to go out of.
    pub interface: String,
    /// `tcp`, `udp`, `icmp`, `icmpv6` or the protocol's number.
    pub protocol: String,
    /// Its source.
    pub source: IpAddr,
    /// Its destination.
    pub destination: IpAddr,
    /// Its destination port (TCP, UDP).
    pub port: Option<u16>,
}

impl LoggedPacket {
    /// The packet a `/dev/kmsg` record logs (`PRIORITY,SEQUENCE,MICROSECONDS,FLAGS;MESSAGE`),
    /// `None` when the record is not one of the table's log rules'.
    #[must_use]
    pub fn parse_record(record: &str) -> Option<Self> {
        let (header, message) = record.split_once(';')?;
        let mut fields = header.split(',');
        let micros: u64 = fields.nth(2)?.parse().ok()?;
        let message = message.lines().next()?;
        let (outbound, line) = match message.strip_prefix(LOG_PREFIX_IN) {
            Some(line) => (false, line),
            None => (true, message.strip_prefix(LOG_PREFIX_OUT)?),
        };
        let field = |key: &str| {
            line.split(' ')
                .find_map(|word| word.strip_prefix(key)?.strip_prefix('='))
        };
        let interface = if outbound { field("OUT") } else { field("IN") }?;
        let protocol = match field("PROTO")? {
            "TCP" => "tcp".to_owned(),
            "UDP" => "udp".to_owned(),
            "ICMP" => "icmp".to_owned(),
            "ICMPv6" => "icmpv6".to_owned(),
            other if other.bytes().all(|b| b.is_ascii_digit()) => other.to_owned(),
            _ => return None,
        };
        let port = match protocol.as_str() {
            "tcp" | "udp" => field("DPT").and_then(|port| port.parse().ok()),
            _ => None,
        };
        Some(Self {
            since_boot: Duration::from_micros(micros),
            key: PacketKind {
                outbound,
                interface: interface.to_owned(),
                protocol,
                source: field("SRC")?.parse().ok()?,
                destination: field("DST")?.parse().ok()?,
                port,
            },
        })
    }
}

/// A kind of packet blocked recently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blocked {
    /// What it was.
    pub kind: PacketKind,
    /// How many times it was logged.
    pub count: u64,
    /// The last time.
    pub last: SystemTime,
}

/// The packets blocked recently: each kind once, the most recent first, [`Self::MAX`] at most.
#[derive(Debug, Default)]
pub struct RecentBlocked {
    blocked: Vec<Blocked>,
}

impl RecentBlocked {
    /// The kinds kept.
    pub const MAX: usize = 32;

    /// Counts `packet`, logged at `at`.
    pub fn record(&mut self, packet: LoggedPacket, at: SystemTime) {
        let count = match self.blocked.iter().position(|b| b.kind == packet.key) {
            Some(index) => self.blocked.remove(index).count.saturating_add(1),
            None => 1,
        };
        self.blocked.insert(
            0,
            Blocked {
                kind: packet.key,
                count,
                last: at,
            },
        );
        self.blocked.truncate(Self::MAX);
    }

    /// Each kind, the most recent first.
    #[must_use]
    pub fn list(&self) -> &[Blocked] {
        &self.blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TCP: &str = "4,812,30000000,-;firewall-controller in: IN=eth0 OUT= \
        MAC=52:54:00:12:34:56:52:55:0a:00:02:02:08:00 SRC=10.0.2.2 DST=10.0.2.15 LEN=60 TOS=0x00 \
        PREC=0x00 TTL=64 ID=54321 DF PROTO=TCP SPT=40000 DPT=23 WINDOW=64240 RES=0x00 SYN URGP=0";

    #[test]
    fn parses_linux_s_log_lines() {
        let packet = LoggedPacket::parse_record(TCP).unwrap();
        assert_eq!(packet.since_boot, Duration::from_secs(30));
        assert_eq!(
            packet.key,
            PacketKind {
                outbound: false,
                interface: "eth0".into(),
                protocol: "tcp".into(),
                source: "10.0.2.2".parse().unwrap(),
                destination: "10.0.2.15".parse().unwrap(),
                port: Some(23),
            }
        );
        let ping = "6,9,1000,-;firewall-controller in: IN=eth0 OUT= MAC= SRC=fec0::2 DST=fec0::15 \
            LEN=104 TC=0 HOPLIMIT=64 FLOWLBL=0 PROTO=ICMPv6 TYPE=128 CODE=0 ID=1 SEQ=1";
        let ping = LoggedPacket::parse_record(ping).unwrap();
        assert_eq!(
            (ping.key.protocol.as_str(), ping.key.port),
            ("icmpv6", None)
        );
        let out = "6,10,1000,-;firewall-controller out: IN= OUT=eth0 SRC=10.0.2.15 DST=1.1.1.1 \
            LEN=60 PROTO=UDP SPT=5000 DPT=53 LEN=40\n SUBSYSTEM=net";
        let out = LoggedPacket::parse_record(out).unwrap();
        assert!(out.key.outbound);
        assert_eq!(
            (out.key.interface.as_str(), out.key.port),
            ("eth0", Some(53))
        );
        let sctp = "6,11,1000,-;firewall-controller in: IN=eth0 OUT= SRC=10.0.2.2 DST=10.0.2.15 \
            PROTO=132";
        assert_eq!(
            LoggedPacket::parse_record(sctp).unwrap().key.protocol,
            "132"
        );
    }

    #[test]
    fn ignores_other_lines() {
        for record in [
            "6,1,1,-;eth0: link up",
            "6,1,1,-;other prefix: IN=eth0 SRC=1.2.3.4 DST=1.2.3.5 PROTO=TCP",
            "6,1,x,-;firewall-controller in: IN=eth0 SRC=1.2.3.4 DST=1.2.3.5 PROTO=TCP",
            "firewall-controller in: IN=eth0 SRC=1.2.3.4 DST=1.2.3.5 PROTO=TCP",
            "6,1,1,-;firewall-controller in: IN=eth0 SRC=nope DST=1.2.3.5 PROTO=TCP",
            "6,1,1,-;firewall-controller in: IN=eth0 SRC=1.2.3.4 DST=1.2.3.5",
        ] {
            assert_eq!(LoggedPacket::parse_record(record), None, "{record}");
        }
    }

    #[test]
    fn groups_the_recent_ones() {
        let mut recent = RecentBlocked::default();
        let packet = LoggedPacket::parse_record(TCP).unwrap();
        let at = |secs| SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        recent.record(packet.clone(), at(1));
        let mut other = packet.clone();
        other.key.port = Some(25);
        recent.record(other, at(2));
        recent.record(packet.clone(), at(3));
        let list = recent.list();
        assert_eq!(list.len(), 2);
        assert_eq!(
            (list[0].kind.port, list[0].count, list[0].last),
            (Some(23), 2, at(3))
        );
        assert_eq!((list[1].kind.port, list[1].count), (Some(25), 1));
        for port in 0..40 {
            let mut many = packet.clone();
            many.key.port = Some(1000 + port);
            recent.record(many, at(10));
        }
        assert_eq!(recent.list().len(), RecentBlocked::MAX);
        assert_eq!(recent.list()[0].kind.port, Some(1039));
    }
}

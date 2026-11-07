//! Ports: a protocol and a range of port numbers, `8080/tcp` or `6000-6010/udp` as text.

use std::fmt;
use std::num::NonZeroU16;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

/// A transport protocol with ports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
}

impl Protocol {
    /// Its IP protocol number (`meta l4proto`).
    #[must_use]
    pub fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
        }
    }

    /// Its name, as nft and the text form of [`Ports`] write it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

impl FromStr for Protocol {
    type Err = InvalidPorts;

    fn from_str(text: &str) -> Result<Self, InvalidPorts> {
        match text {
            "tcp" => Ok(Self::Tcp),
            "udp" => Ok(Self::Udp),
            _ => Err(InvalidPorts::Protocol(text.to_owned())),
        }
    }
}

/// Why ports are invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidPorts {
    /// Not `tcp` or `udp`.
    #[error("{0:?} is not a protocol: tcp or udp")]
    Protocol(String),
    /// Not 1 to 65535.
    #[error("{0} is not a port: 1 to 65535")]
    Port(String),
    /// A range whose first port is after its last.
    #[error("the range {0}-{1} ends before it starts")]
    Reversed(u16, u16),
    /// Not `PORT/PROTOCOL` or `FIRST-LAST/PROTOCOL`.
    #[error("{0:?} is not PORT/PROTOCOL or FIRST-LAST/PROTOCOL (8080/tcp, 6000-6010/udp)")]
    Syntax(String),
}

/// A port: 1 to 65535.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Port(NonZeroU16);

impl Port {
    /// `number`, which must not be 0.
    #[must_use]
    pub const fn new(number: NonZeroU16) -> Self {
        Self(number)
    }

    /// Its number.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0.get()
    }
}

impl TryFrom<u32> for Port {
    type Error = InvalidPorts;

    fn try_from(number: u32) -> Result<Self, InvalidPorts> {
        u16::try_from(number)
            .ok()
            .and_then(NonZeroU16::new)
            .map(Self)
            .ok_or_else(|| InvalidPorts::Port(number.to_string()))
    }
}

impl FromStr for Port {
    type Err = InvalidPorts;

    fn from_str(text: &str) -> Result<Self, InvalidPorts> {
        // Digits only: no sign, no spaces.
        if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
            return Err(InvalidPorts::Port(text.to_owned()));
        }
        let number: u32 = text
            .parse()
            .map_err(|_| InvalidPorts::Port(text.to_owned()))?;
        Self::try_from(number)
    }
}

impl fmt::Display for Port {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A protocol's port, or range of ports (`first <= last`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ports {
    protocol: Protocol,
    first: Port,
    last: Port,
}

impl Ports {
    /// `first` to `last` of `protocol`.
    pub fn new(protocol: Protocol, first: Port, last: Port) -> Result<Self, InvalidPorts> {
        if first > last {
            return Err(InvalidPorts::Reversed(first.get(), last.get()));
        }
        Ok(Self {
            protocol,
            first,
            last,
        })
    }

    /// The single `port` of `protocol`.
    #[must_use]
    pub const fn one(protocol: Protocol, port: Port) -> Self {
        Self {
            protocol,
            first: port,
            last: port,
        }
    }

    /// `first` to `last` of `protocol`, which the caller checked are in order (constants).
    pub(crate) const fn from_parts(protocol: Protocol, first: Port, last: Port) -> Self {
        Self {
            protocol,
            first,
            last,
        }
    }

    /// The protocol.
    #[must_use]
    pub fn protocol(self) -> Protocol {
        self.protocol
    }

    /// The first port.
    #[must_use]
    pub fn first(self) -> Port {
        self.first
    }

    /// The last port, the first's for a single one.
    #[must_use]
    pub fn last(self) -> Port {
        self.last
    }

    /// Whether they include `port` of `protocol`.
    #[must_use]
    pub fn covers(self, protocol: Protocol, port: Port) -> bool {
        self.protocol == protocol && self.first <= port && port <= self.last
    }

    /// The ports without the protocol: `22` or `6000-6010`, as nft writes them.
    #[must_use]
    pub fn range_text(self) -> String {
        if self.first == self.last {
            self.first.to_string()
        } else {
            format!("{}-{}", self.first, self.last)
        }
    }
}

impl fmt::Display for Ports {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.range_text(), self.protocol)
    }
}

impl FromStr for Ports {
    type Err = InvalidPorts;

    fn from_str(text: &str) -> Result<Self, InvalidPorts> {
        let syntax = || InvalidPorts::Syntax(text.to_owned());
        let (range, protocol) = text.split_once('/').ok_or_else(syntax)?;
        let protocol = protocol.parse()?;
        match range.split_once('-') {
            Some((first, last)) => Self::new(protocol, first.parse()?, last.parse()?),
            None => Ok(Self::one(protocol, range.parse()?)),
        }
    }
}

impl Serialize for Ports {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Ports {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_round_trips() {
        for text in ["22/tcp", "6000-6010/udp", "1-65535/tcp", "53/udp"] {
            let ports: Ports = text.parse().unwrap();
            assert_eq!(ports.to_string(), text);
        }
        let range: Ports = "6000-6010/udp".parse().unwrap();
        assert_eq!(range.protocol(), Protocol::Udp);
        assert_eq!((range.first().get(), range.last().get()), (6000, 6010));
        assert_eq!(range.range_text(), "6000-6010");
        let port = |number| Port::try_from(number).unwrap();
        assert!(range.covers(Protocol::Udp, port(6000)) && range.covers(Protocol::Udp, port(6010)));
        assert!(
            !range.covers(Protocol::Udp, port(6011)) && !range.covers(Protocol::Tcp, port(6005))
        );
        let same: Ports = "80-80/tcp".parse().unwrap();
        assert_eq!(same.to_string(), "80/tcp", "a range of one is the port");
    }

    #[test]
    fn rejects_invalid_ports() {
        for (text, error) in [
            ("22", InvalidPorts::Syntax("22".into())),
            ("22/sctp", InvalidPorts::Protocol("sctp".into())),
            ("0/tcp", InvalidPorts::Port("0".into())),
            ("65536/tcp", InvalidPorts::Port("65536".into())),
            ("+22/tcp", InvalidPorts::Port("+22".into())),
            ("/tcp", InvalidPorts::Port(String::new())),
            ("10-5/udp", InvalidPorts::Reversed(10, 5)),
            ("1-2-3/udp", InvalidPorts::Port("2-3".into())),
            ("22/TCP", InvalidPorts::Protocol("TCP".into())),
        ] {
            assert_eq!(text.parse::<Ports>(), Err(error), "{text}");
        }
        assert!(Port::try_from(0).is_err());
        assert!(Port::try_from(70_000).is_err());
        assert_eq!(Port::try_from(443).unwrap().get(), 443);
    }

    #[test]
    fn serializes_as_text() {
        let ports: Ports = "8080/tcp".parse().unwrap();
        assert_eq!(serde_json::to_string(&ports).unwrap(), r#""8080/tcp""#);
        assert_eq!(
            serde_json::from_str::<Ports>(r#""8080/tcp""#).unwrap(),
            ports
        );
        assert!(serde_json::from_str::<Ports>(r#""0/tcp""#).is_err());
    }
}

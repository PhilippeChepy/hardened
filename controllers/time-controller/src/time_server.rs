//! NTP servers.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use controllers_helpers::{Hostname, InvalidValue};
use serde::{Deserialize, Serialize};

/// An NTP server: a host name to resolve, or an IP address to query as is. Written as either.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum TimeServer {
    /// A name, resolved before each query (a pool name resolves to several servers).
    Host(Hostname),
    /// An address.
    Address(IpAddr),
}

impl TryFrom<String> for TimeServer {
    type Error = InvalidValue;

    fn try_from(server: String) -> Result<Self, Self::Error> {
        if let Ok(address) = server.parse() {
            return Ok(Self::Address(address));
        }
        server.parse().map(Self::Host).map_err(|_: InvalidValue| {
            InvalidValue::new(
                "time server",
                &server,
                "must be a host name or an IP address",
            )
        })
    }
}

impl FromStr for TimeServer {
    type Err = InvalidValue;

    fn from_str(server: &str) -> Result<Self, Self::Err> {
        Self::try_from(server.to_owned())
    }
}

impl From<TimeServer> for String {
    fn from(server: TimeServer) -> Self {
        server.to_string()
    }
}

impl fmt::Display for TimeServer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Host(host) => host.fmt(f),
            Self::Address(address) => address.fmt(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn time_servers() {
        assert!(matches!(
            "time.example.com".parse(),
            Ok(TimeServer::Host(host)) if host.as_str() == "time.example.com"
        ));
        for address in ["192.0.2.123", "2001:db8::123"] {
            let server: TimeServer = address.parse().unwrap();
            assert_eq!(server, TimeServer::Address(address.parse().unwrap()));
            assert_eq!(server.to_string(), address);
        }
        assert!("ntp://time.example".parse::<TimeServer>().is_err());
        assert!("".parse::<TimeServer>().is_err());
    }
}

//! IPv4 addresses on an interface, with their subnet.

use std::fmt;
use std::net::Ipv4Addr;
use std::str::FromStr;

use controllers_helpers::InvalidValue;
use serde::Deserialize;
use serde::Serialize;

/// A unicast IPv4 address an interface can have, and the length of its subnet's prefix (1 to
/// 32), as `192.0.2.10/24`. Below /31, it is neither its subnet's network address nor its
/// broadcast address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv4Address {
    address: Ipv4Addr,
    prefix_len: u8,
}

impl Ipv4Address {
    /// `address/prefix_len`, if an interface can have it.
    pub fn new(address: Ipv4Addr, prefix_len: u8) -> Result<Self, InvalidValue> {
        let invalid = |reason| {
            Err(InvalidValue::new(
                "IPv4 address",
                &format!("{address}/{prefix_len}"),
                reason,
            ))
        };
        if !(1..=32).contains(&prefix_len) {
            return invalid("the prefix length must be 1 to 32");
        }
        if address.is_unspecified()
            || address.is_loopback()
            || address.is_multicast()
            || address.is_broadcast()
            || address.octets()[0] == 0
            || address.octets()[0] >= 240
        {
            return invalid("must be a unicast address");
        }
        let candidate = Self {
            address,
            prefix_len,
        };
        if prefix_len < 31 && (address == candidate.network() || address == candidate.broadcast()) {
            return invalid("must not be its subnet's network or broadcast address");
        }
        Ok(candidate)
    }

    /// The address.
    #[must_use]
    pub fn address(&self) -> Ipv4Addr {
        self.address
    }

    /// The length of its subnet's prefix.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Its subnet's mask, as a number.
    #[must_use]
    fn mask(&self) -> u32 {
        u32::MAX
            .checked_shl(32 - u32::from(self.prefix_len))
            .unwrap_or(0)
    }

    /// Its subnet's network address.
    #[must_use]
    pub fn network(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.address) & self.mask())
    }

    /// Its subnet's broadcast address.
    #[must_use]
    fn broadcast(&self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.address) | !self.mask())
    }

    /// Whether `other` is in its subnet, which a /32 has none of but itself.
    #[must_use]
    pub fn contains(&self, other: Ipv4Addr) -> bool {
        u32::from(other) & self.mask() == u32::from(self.network())
    }
}

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_len)
    }
}

impl FromStr for Ipv4Address {
    type Err = InvalidValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let invalid = |reason| InvalidValue::new("IPv4 address", text, reason);
        let (address, prefix_len) = text
            .split_once('/')
            .ok_or_else(|| invalid("must be ADDRESS/PREFIX-LENGTH"))?;
        let address = address
            .parse()
            .map_err(|_| invalid("not an IPv4 address"))?;
        let prefix_len = prefix_len
            .parse()
            .map_err(|_| invalid("the prefix length must be 1 to 32"))?;
        Self::new(address, prefix_len)
    }
}

impl TryFrom<String> for Ipv4Address {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<Ipv4Address> for String {
    fn from(address: Ipv4Address) -> Self {
        address.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_host_addresses() {
        let address: Ipv4Address = "192.0.2.10/24".parse().unwrap();
        assert_eq!(address.address(), Ipv4Addr::new(192, 0, 2, 10));
        assert_eq!(address.prefix_len(), 24);
        assert_eq!(address.network(), Ipv4Addr::new(192, 0, 2, 0));
        assert!(address.contains(Ipv4Addr::new(192, 0, 2, 1)));
        assert!(!address.contains(Ipv4Addr::new(192, 0, 3, 1)));
        assert_eq!(address.to_string(), "192.0.2.10/24");
        for valid in ["10.0.0.0/31", "10.0.0.1/31", "10.0.0.5/32", "172.16.0.1/12"] {
            assert!(valid.parse::<Ipv4Address>().is_ok(), "{valid}");
        }
        let host: Ipv4Address = "10.0.0.5/32".parse().unwrap();
        assert!(!host.contains(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn rejects_what_an_interface_cannot_have() {
        for invalid in [
            "192.0.2.10",
            "192.0.2.10/0",
            "192.0.2.10/33",
            "192.0.2.10/-1",
            "192.0.2/24",
            "2001:db8::1/64",
            "192.0.2.0/24",
            "192.0.2.255/24",
            "0.0.0.0/8",
            "0.1.2.3/8",
            "127.0.0.1/8",
            "224.0.0.1/4",
            "240.0.0.1/4",
            "255.255.255.255/32",
        ] {
            assert!(invalid.parse::<Ipv4Address>().is_err(), "{invalid}");
        }
    }

    #[test]
    fn serializes_as_text() {
        let address: Ipv4Address = "192.0.2.10/24".parse().unwrap();
        let json = serde_json::to_string(&address).unwrap();
        assert_eq!(json, "\"192.0.2.10/24\"");
        assert_eq!(serde_json::from_str::<Ipv4Address>(&json).unwrap(), address);
        assert!(serde_json::from_str::<Ipv4Address>("\"192.0.2.0/24\"").is_err());
    }
}

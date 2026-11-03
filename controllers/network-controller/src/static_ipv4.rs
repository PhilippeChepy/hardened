//! IPv4 addresses configured statically.

use std::net::Ipv4Addr;

use controllers_helpers::NonEmpty;
use serde::Deserialize;
use serde::Serialize;

use crate::Ipv4Address;

/// Addresses configured statically on an interface: at least one, all different, and the
/// default route's gateway, if any, in the subnet of one of them (the interface reaches it
/// directly) and not one of them. The first address is the default route's source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawStaticIpv4", into = "RawStaticIpv4")]
pub struct StaticIpv4 {
    addresses: NonEmpty<Ipv4Address>,
    gateway: Option<Ipv4Addr>,
}

/// Why addresses were refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidStaticIpv4 {
    /// No address.
    #[error("at least one address is required")]
    NoAddress,
    /// An address twice.
    #[error("{0} is configured twice")]
    DuplicateAddress(Ipv4Addr),
    /// A gateway no unicast route can go through.
    #[error("gateway {0} is not a unicast address")]
    InvalidGateway(Ipv4Addr),
    /// A gateway the interface has.
    #[error("gateway {0} is one of the interface's addresses")]
    LocalGateway(Ipv4Addr),
    /// A gateway outside the subnets.
    #[error("gateway {0} is not in the subnet of any of the addresses")]
    UnreachableGateway(Ipv4Addr),
}

impl StaticIpv4 {
    /// `addresses`, with `gateway` as the default route's next hop.
    pub fn new(
        addresses: Vec<Ipv4Address>,
        gateway: Option<Ipv4Addr>,
    ) -> Result<Self, InvalidStaticIpv4> {
        for (i, address) in addresses.iter().enumerate() {
            if addresses[..i]
                .iter()
                .any(|other| other.address() == address.address())
            {
                return Err(InvalidStaticIpv4::DuplicateAddress(address.address()));
            }
        }
        if let Some(gateway) = gateway {
            if gateway.is_unspecified()
                || gateway.is_loopback()
                || gateway.is_multicast()
                || gateway.is_broadcast()
            {
                return Err(InvalidStaticIpv4::InvalidGateway(gateway));
            }
            if addresses.iter().any(|address| address.address() == gateway) {
                return Err(InvalidStaticIpv4::LocalGateway(gateway));
            }
            if !addresses
                .iter()
                .any(|address| address.prefix_len() < 32 && address.contains(gateway))
            {
                return Err(InvalidStaticIpv4::UnreachableGateway(gateway));
            }
        }
        let addresses = NonEmpty::from_vec(addresses).ok_or(InvalidStaticIpv4::NoAddress)?;
        Ok(Self { addresses, gateway })
    }

    /// The addresses, the default route's source first.
    #[must_use]
    pub fn addresses(&self) -> &NonEmpty<Ipv4Address> {
        &self.addresses
    }

    /// The default route's next hop, if any.
    #[must_use]
    pub fn gateway(&self) -> Option<Ipv4Addr> {
        self.gateway
    }

    /// The address the default route goes out from: the first one in the gateway's subnet.
    #[must_use]
    pub fn gateway_source(&self) -> Option<Ipv4Addr> {
        let gateway = self.gateway?;
        self.addresses
            .iter()
            .find(|address| address.contains(gateway))
            .map(Ipv4Address::address)
    }
}

/// The persisted form, validated into a [`StaticIpv4`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawStaticIpv4 {
    addresses: Vec<Ipv4Address>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    gateway: Option<Ipv4Addr>,
}

impl TryFrom<RawStaticIpv4> for StaticIpv4 {
    type Error = InvalidStaticIpv4;

    fn try_from(raw: RawStaticIpv4) -> Result<Self, Self::Error> {
        Self::new(raw.addresses, raw.gateway)
    }
}

impl From<StaticIpv4> for RawStaticIpv4 {
    fn from(addresses: StaticIpv4) -> Self {
        Self {
            addresses: addresses.addresses.into_iter().collect(),
            gateway: addresses.gateway,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addresses(list: &[&str]) -> Vec<Ipv4Address> {
        list.iter()
            .map(|address| address.parse().unwrap())
            .collect()
    }

    fn gateway(text: &str) -> Option<Ipv4Addr> {
        Some(text.parse().unwrap())
    }

    #[test]
    fn accepts_a_reachable_gateway() {
        let config = StaticIpv4::new(
            addresses(&["10.0.0.5/32", "192.0.2.10/24"]),
            gateway("192.0.2.1"),
        )
        .unwrap();
        assert_eq!(config.gateway_source(), Some(Ipv4Addr::new(192, 0, 2, 10)));
        assert_eq!(config.addresses().first().to_string(), "10.0.0.5/32");
        let without = StaticIpv4::new(addresses(&["192.0.2.10/24"]), None).unwrap();
        assert_eq!(without.gateway_source(), None);
        assert!(StaticIpv4::new(addresses(&["10.0.0.0/31"]), gateway("10.0.0.1")).is_ok());
    }

    #[test]
    fn refuses_inconsistent_addresses() {
        use InvalidStaticIpv4::*;
        let ip = |text: &str| text.parse::<Ipv4Addr>().unwrap();
        for (list, via, error) in [
            (&[][..], None, NoAddress),
            (
                &["192.0.2.10/24", "192.0.2.10/25"][..],
                None,
                DuplicateAddress(ip("192.0.2.10")),
            ),
            (
                &["192.0.2.10/24"][..],
                gateway("198.51.100.1"),
                UnreachableGateway(ip("198.51.100.1")),
            ),
            (
                &["192.0.2.10/32"][..],
                gateway("192.0.2.1"),
                UnreachableGateway(ip("192.0.2.1")),
            ),
            (
                &["192.0.2.10/24"][..],
                gateway("192.0.2.10"),
                LocalGateway(ip("192.0.2.10")),
            ),
            (
                &["192.0.2.10/24"][..],
                gateway("0.0.0.0"),
                InvalidGateway(Ipv4Addr::UNSPECIFIED),
            ),
            (
                &["192.0.2.10/24"][..],
                gateway("255.255.255.255"),
                InvalidGateway(Ipv4Addr::BROADCAST),
            ),
        ] {
            assert_eq!(
                StaticIpv4::new(addresses(list), via),
                Err(error),
                "{list:?}"
            );
        }
    }

    #[test]
    fn round_trips_through_json() {
        let config = StaticIpv4::new(addresses(&["192.0.2.10/24"]), gateway("192.0.2.1")).unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(
            json,
            r#"{"addresses":["192.0.2.10/24"],"gateway":"192.0.2.1"}"#
        );
        assert_eq!(serde_json::from_str::<StaticIpv4>(&json).unwrap(), config);
        let unreachable = r#"{"addresses":["192.0.2.10/24"],"gateway":"10.0.0.1"}"#;
        assert!(serde_json::from_str::<StaticIpv4>(unreachable).is_err());
    }
}

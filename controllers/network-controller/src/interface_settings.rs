//! How network-controller configures one physical Ethernet interface.

use std::net::IpAddr;

use serde::Deserialize;
use serde::Serialize;

use crate::DnsSettings;
use crate::Mtu;
use crate::StaticIpv4;

/// How an interface gets its IPv4 address.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum Ipv4Method {
    /// A DHCPv4 lease, renewed.
    #[default]
    Dhcp,
    /// Addresses configured statically.
    Static(StaticIpv4),
}

/// An interface's configuration. The default is what network-controller does without one:
/// enabled, DHCP, the DNS servers DHCP gives, the MTU left as it is (DHCP's, under DHCP). IPv6 is
/// the kernel's SLAAC whatever the configuration, on an enabled interface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawInterfaceSettings", into = "RawInterfaceSettings")]
pub struct InterfaceSettings {
    enabled: bool,
    ipv4: Ipv4Method,
    dns: DnsSettings,
    mtu: Option<Mtu>,
}

impl Default for InterfaceSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            ipv4: Ipv4Method::Dhcp,
            dns: DnsSettings::default(),
            mtu: None,
        }
    }
}

/// Why an interface's resolver configuration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidInterfaceDns {
    /// More name servers than the resolver uses.
    #[error("at most {max} name servers", max = InterfaceSettings::MAX_NAME_SERVERS)]
    TooManyNameServers,
    /// More search domains than the resolver uses.
    #[error("at most {max} search domains", max = InterfaceSettings::MAX_SEARCH_DOMAINS)]
    TooManySearchDomains,
    /// A name server no query can be sent to.
    #[error("name server {0} is not a unicast address")]
    InvalidNameServer(IpAddr),
    /// A name server twice.
    #[error("name server {0} is configured twice")]
    DuplicateNameServer(IpAddr),
    /// A search domain twice.
    #[error("search domain {0} is configured twice")]
    DuplicateSearchDomain(String),
}

impl InterfaceSettings {
    /// The name servers musl's and glibc's resolvers use (`MAXNS`).
    pub const MAX_NAME_SERVERS: usize = 3;
    /// The search domains glibc's resolver used to take (`MAXDNSRCH`).
    pub const MAX_SEARCH_DOMAINS: usize = 6;

    /// The configuration of an interface `enabled` or not, its IPv4 addresses from `ipv4`, its
    /// resolver's `dns` (each list, when not empty, replacing what DHCP gives on it) and `mtu`.
    pub fn new(
        enabled: bool,
        ipv4: Ipv4Method,
        dns: DnsSettings,
        mtu: Option<Mtu>,
    ) -> Result<Self, InvalidInterfaceDns> {
        if dns.name_servers.len() > Self::MAX_NAME_SERVERS {
            return Err(InvalidInterfaceDns::TooManyNameServers);
        }
        if dns.search_list.len() > Self::MAX_SEARCH_DOMAINS {
            return Err(InvalidInterfaceDns::TooManySearchDomains);
        }
        for (i, &server) in dns.name_servers.iter().enumerate() {
            if !is_unicast(server) {
                return Err(InvalidInterfaceDns::InvalidNameServer(server));
            }
            if dns.name_servers[..i].contains(&server) {
                return Err(InvalidInterfaceDns::DuplicateNameServer(server));
            }
        }
        for (i, domain) in dns.search_list.iter().enumerate() {
            if dns.search_list[..i].contains(domain) {
                return Err(InvalidInterfaceDns::DuplicateSearchDomain(
                    domain.to_string(),
                ));
            }
        }
        Ok(Self {
            enabled,
            ipv4,
            dns,
            mtu,
        })
    }

    /// Whether the interface is up and configured; a disabled one is set down.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// How it gets its IPv4 address.
    #[must_use]
    pub fn ipv4(&self) -> &Ipv4Method {
        &self.ipv4
    }

    /// Its resolver: each list, when not empty, replaces what DHCP gives on it.
    #[must_use]
    pub fn dns(&self) -> &DnsSettings {
        &self.dns
    }

    /// Its MTU, if set: DHCP's otherwise, or left as it is.
    #[must_use]
    pub fn mtu(&self) -> Option<Mtu> {
        self.mtu
    }

    /// Its static addresses, if it is enabled and has some.
    #[must_use]
    pub fn static_ipv4(&self) -> Option<&StaticIpv4> {
        match &self.ipv4 {
            Ipv4Method::Static(addresses) if self.enabled => Some(addresses),
            _ => None,
        }
    }
}

/// Whether queries can be sent to `address`.
fn is_unicast(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            !(address.is_unspecified() || address.is_multicast() || address.is_broadcast())
        }
        IpAddr::V6(address) => !(address.is_unspecified() || address.is_multicast()),
    }
}

/// The persisted form, validated into an [`InterfaceSettings`].
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawInterfaceSettings {
    #[serde(default = "enabled")]
    enabled: bool,
    #[serde(default)]
    ipv4: Ipv4Method,
    #[serde(default)]
    dns: DnsSettings,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mtu: Option<Mtu>,
}

/// The default of `enabled`.
fn enabled() -> bool {
    true
}

impl TryFrom<RawInterfaceSettings> for InterfaceSettings {
    type Error = InvalidInterfaceDns;

    fn try_from(raw: RawInterfaceSettings) -> Result<Self, Self::Error> {
        Self::new(raw.enabled, raw.ipv4, raw.dns, raw.mtu)
    }
}

impl From<InterfaceSettings> for RawInterfaceSettings {
    fn from(settings: InterfaceSettings) -> Self {
        Self {
            enabled: settings.enabled,
            ipv4: settings.ipv4,
            dns: settings.dns,
            mtu: settings.mtu,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns(name_servers: &[&str], search_list: &[&str]) -> DnsSettings {
        DnsSettings {
            name_servers: name_servers.iter().map(|s| s.parse().unwrap()).collect(),
            search_list: search_list.iter().map(|s| s.parse().unwrap()).collect(),
        }
    }

    fn with_dns(dns: DnsSettings) -> Result<InterfaceSettings, InvalidInterfaceDns> {
        InterfaceSettings::new(true, Ipv4Method::Dhcp, dns, None)
    }

    #[test]
    fn checks_the_resolver() {
        use InvalidInterfaceDns::*;
        assert!(
            with_dns(dns(
                &["192.0.2.53", "2001:db8::53", "9.9.9.9"],
                &["a.example"]
            ))
            .is_ok()
        );
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        for (dns, error) in [
            (
                dns(&["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"], &[]),
                TooManyNameServers,
            ),
            (
                dns(
                    &[],
                    &[
                        "a.example",
                        "b.example",
                        "c.example",
                        "d.example",
                        "e.example",
                        "f.example",
                        "g.example",
                    ],
                ),
                TooManySearchDomains,
            ),
            (dns(&["0.0.0.0"], &[]), InvalidNameServer(ip("0.0.0.0"))),
            (dns(&["ff02::1"], &[]), InvalidNameServer(ip("ff02::1"))),
            (
                dns(&["255.255.255.255"], &[]),
                InvalidNameServer(ip("255.255.255.255")),
            ),
            (
                dns(&["1.1.1.1", "1.1.1.1"], &[]),
                DuplicateNameServer(ip("1.1.1.1")),
            ),
            (
                dns(&[], &["a.example", "a.example"]),
                DuplicateSearchDomain("a.example".to_owned()),
            ),
        ] {
            assert_eq!(with_dns(dns.clone()), Err(error), "{dns:?}");
        }
    }

    #[test]
    fn round_trips_through_json() {
        assert_eq!(
            serde_json::to_string(&InterfaceSettings::default()).unwrap(),
            r#"{"enabled":true,"ipv4":"dhcp","dns":{}}"#
        );
        assert_eq!(
            serde_json::from_str::<InterfaceSettings>("{}").unwrap(),
            InterfaceSettings::default()
        );
        let addresses = StaticIpv4::new(
            vec!["192.0.2.10/24".parse().unwrap()],
            Some("192.0.2.1".parse().unwrap()),
        )
        .unwrap();
        let settings = InterfaceSettings::new(
            false,
            Ipv4Method::Static(addresses),
            dns(&["192.0.2.53"], &["corp.example"]),
            Some(Mtu::try_from(9000).unwrap()),
        )
        .unwrap();
        let json = serde_json::to_string(&settings).unwrap();
        assert_eq!(
            json,
            r#"{"enabled":false,"ipv4":{"static":{"addresses":["192.0.2.10/24"],"gateway":"192.0.2.1"}},"dns":{"name-servers":["192.0.2.53"],"search-list":["corp.example"]},"mtu":9000}"#
        );
        assert_eq!(
            serde_json::from_str::<InterfaceSettings>(&json).unwrap(),
            settings
        );
        assert_eq!(settings.static_ipv4(), None, "disabled");
        assert!(serde_json::from_str::<InterfaceSettings>(r#"{"mtu":100}"#).is_err());
        assert!(
            serde_json::from_str::<InterfaceSettings>(r#"{"dns":{"name-servers":["0.0.0.0"]}}"#)
                .is_err()
        );
    }
}

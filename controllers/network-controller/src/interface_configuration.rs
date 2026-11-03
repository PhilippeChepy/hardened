//! An interface's configuration as network-controller's API carries it.

use std::net::Ipv4Addr;

use controllers_helpers::InvalidMessage;
use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::FieldResult as _;
use controllers_helpers::invalid_message::WithinResult as _;

use crate::DnsSettings;
use crate::InterfaceSettings;
use crate::Ipv4Address;
use crate::Ipv4Method;
use crate::Mtu;
use crate::StaticIpv4;
use crate::network;
use crate::network::interface_config::Ipv4;

impl From<Ipv4Address> for network::Ipv4Address {
    fn from(address: Ipv4Address) -> Self {
        Self {
            address: address.address().to_string(),
            prefix_length: address.prefix_len().into(),
        }
    }
}

impl TryFrom<network::Ipv4Address> for Ipv4Address {
    type Error = InvalidMessage;

    fn try_from(message: network::Ipv4Address) -> Result<Self, Self::Error> {
        let address = message
            .address
            .parse::<Ipv4Addr>()
            .map_err(|_| format!("{:?} is not an IPv4 address", message.address))
            .field("address")?;
        let prefix_len = u8::try_from(message.prefix_length)
            .map_err(|_| "must be 1 to 32")
            .field("prefix_length")?;
        Ipv4Address::new(address, prefix_len).map_err(InvalidMessage::whole)
    }
}

impl From<StaticIpv4> for network::StaticIpv4 {
    fn from(addresses: StaticIpv4) -> Self {
        Self {
            addresses: addresses
                .addresses()
                .iter()
                .copied()
                .map(network::Ipv4Address::from)
                .collect(),
            gateway: addresses.gateway().map(|gateway| gateway.to_string()),
        }
    }
}

impl TryFrom<network::StaticIpv4> for StaticIpv4 {
    type Error = InvalidMessage;

    fn try_from(message: network::StaticIpv4) -> Result<Self, Self::Error> {
        let addresses = invalid_message::convert_each(message.addresses, "addresses", |address| {
            Ipv4Address::try_from(address)
        })?;
        let gateway = message
            .gateway
            .map(|gateway| {
                gateway
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("{gateway:?} is not an IPv4 address"))
            })
            .transpose()
            .field("gateway")?;
        StaticIpv4::new(addresses, gateway).map_err(InvalidMessage::whole)
    }
}

impl From<InterfaceSettings> for network::InterfaceConfig {
    fn from(settings: InterfaceSettings) -> Self {
        Self {
            disabled: !settings.enabled(),
            ipv4: Some(match settings.ipv4().clone() {
                Ipv4Method::Dhcp => Ipv4::Dhcp(()),
                Ipv4Method::Static(addresses) => Ipv4::StaticIpv4(addresses.into()),
            }),
            dns: Some(settings.dns().clone().into()),
            mtu: settings.mtu().map(u32::from),
        }
    }
}

impl TryFrom<network::InterfaceConfig> for InterfaceSettings {
    type Error = InvalidMessage;

    fn try_from(message: network::InterfaceConfig) -> Result<Self, Self::Error> {
        let ipv4 = match message.ipv4 {
            None | Some(Ipv4::Dhcp(())) => Ipv4Method::Dhcp,
            Some(Ipv4::StaticIpv4(addresses)) => {
                Ipv4Method::Static(StaticIpv4::try_from(addresses).within("static_ipv4")?)
            }
        };
        let dns = message
            .dns
            .map(DnsSettings::try_from)
            .transpose()
            .within("dns")?
            .unwrap_or_default();
        let mtu = message.mtu.map(Mtu::try_from).transpose().field("mtu")?;
        InterfaceSettings::new(!message.disabled, ipv4, dns, mtu).field("dns")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(address: &str, prefix_length: u32) -> network::Ipv4Address {
        network::Ipv4Address {
            address: address.to_owned(),
            prefix_length,
        }
    }

    fn static_config(
        addresses: Vec<network::Ipv4Address>,
        gateway: &str,
    ) -> network::InterfaceConfig {
        network::InterfaceConfig {
            ipv4: Some(Ipv4::StaticIpv4(network::StaticIpv4 {
                addresses,
                gateway: Some(gateway.to_owned()),
            })),
            ..network::InterfaceConfig::default()
        }
    }

    #[test]
    fn the_default_message_is_the_default_configuration() {
        let settings = InterfaceSettings::try_from(network::InterfaceConfig::default()).unwrap();
        assert_eq!(settings, InterfaceSettings::default());
        let message = network::InterfaceConfig::from(InterfaceSettings::default());
        assert_eq!(message.ipv4, Some(Ipv4::Dhcp(())));
        assert!(!message.disabled);
        assert_eq!(InterfaceSettings::try_from(message).unwrap(), settings);
    }

    #[test]
    fn round_trips() {
        let mut message = static_config(vec![address("192.0.2.10", 24)], "192.0.2.1");
        message.disabled = true;
        message.mtu = Some(9000);
        message.dns = Some(network::Configuration {
            name_servers: vec!["192.0.2.53".to_owned()],
            search_list: vec!["corp.example".to_owned()],
        });
        let settings = InterfaceSettings::try_from(message.clone()).unwrap();
        assert!(!settings.enabled());
        assert_eq!(settings.mtu().map(Mtu::get), Some(9000));
        assert_eq!(network::InterfaceConfig::from(settings), message);
    }

    #[test]
    fn errors_name_the_field() {
        for (message, field) in [
            (
                static_config(vec![address("192.0.2.10", 33)], "192.0.2.1"),
                "static_ipv4.addresses[0]",
            ),
            (
                static_config(vec![address("eth0", 24)], "192.0.2.1"),
                "static_ipv4.addresses[0]",
            ),
            (
                static_config(vec![address("192.0.2.0", 24)], "192.0.2.1"),
                "static_ipv4.addresses[0]",
            ),
            (
                static_config(vec![address("192.0.2.10", 24)], "router"),
                "static_ipv4.gateway",
            ),
            (
                static_config(vec![address("192.0.2.10", 24)], "10.0.0.1"),
                "static_ipv4",
            ),
            (static_config(Vec::new(), "10.0.0.1"), "static_ipv4"),
            (
                network::InterfaceConfig {
                    mtu: Some(100),
                    ..network::InterfaceConfig::default()
                },
                "mtu",
            ),
            (
                network::InterfaceConfig {
                    dns: Some(network::Configuration {
                        name_servers: vec!["ns1.example".to_owned()],
                        search_list: Vec::new(),
                    }),
                    ..network::InterfaceConfig::default()
                },
                "dns.name_servers[0]",
            ),
            (
                network::InterfaceConfig {
                    dns: Some(network::Configuration {
                        name_servers: vec!["0.0.0.0".to_owned()],
                        search_list: Vec::new(),
                    }),
                    ..network::InterfaceConfig::default()
                },
                "dns",
            ),
        ] {
            let error = InterfaceSettings::try_from(message.clone()).unwrap_err();
            assert_eq!(error.field(), field, "{error} for {message:?}");
        }
    }
}

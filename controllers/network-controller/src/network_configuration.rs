//! `settings.dns` as network-controller's configuration.

use std::net::IpAddr;

use controllers_helpers::DomainName;
use controllers_helpers::InvalidMessage;
use controllers_helpers::invalid_message;

use crate::DnsSettings;
use crate::network;

impl From<DnsSettings> for network::Configuration {
    fn from(dns: DnsSettings) -> Self {
        Self {
            name_servers: dns.name_servers.iter().map(IpAddr::to_string).collect(),
            search_list: dns.search_list.into_iter().map(String::from).collect(),
        }
    }
}

impl TryFrom<network::Configuration> for DnsSettings {
    type Error = InvalidMessage;

    fn try_from(message: network::Configuration) -> Result<Self, Self::Error> {
        Ok(Self {
            name_servers: invalid_message::convert_each(
                message.name_servers,
                "name_servers",
                |server| server.parse::<IpAddr>(),
            )?,
            search_list: invalid_message::convert_each(
                message.search_list,
                "search_list",
                DomainName::try_from,
            )?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let dns = DnsSettings {
            name_servers: vec![
                "192.0.2.53".parse().unwrap(),
                "2001:db8::53".parse().unwrap(),
            ],
            search_list: vec!["corp.example.com".parse().unwrap()],
        };
        let message = network::Configuration::from(dns.clone());
        assert_eq!(message.name_servers, ["192.0.2.53", "2001:db8::53"]);
        assert_eq!(DnsSettings::try_from(message).unwrap(), dns);
    }

    #[test]
    fn rejects_invalid_values() {
        let error = DnsSettings::try_from(network::Configuration {
            name_servers: vec!["192.0.2.53".to_owned(), "ns1.example.com".to_owned()],
            search_list: Vec::new(),
        })
        .unwrap_err();
        assert_eq!(error.field(), "name_servers[1]");
        let error = DnsSettings::try_from(network::Configuration {
            name_servers: Vec::new(),
            search_list: vec!["a\nnameserver 192.0.2.1".to_owned()],
        })
        .unwrap_err();
        assert_eq!(error.field(), "search_list[0]");
    }
}

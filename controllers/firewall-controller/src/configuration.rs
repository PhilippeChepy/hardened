//! The configuration as `hardened.firewall.v1`'s messages, and back: validated once, here.

use controllers_helpers::InvalidMessage;
use controllers_helpers::invalid_message::FieldResult as _;
use controllers_helpers::invalid_message::WithinResult as _;

use crate::firewall;
use crate::policy::Allowed;
use crate::policy::AllowedList;
use crate::policy::FirewallConfig;
use crate::policy::Inbound;
use crate::policy::Outbound;
use crate::ports::Port;
use crate::ports::Ports;
use crate::ports::Protocol;
use crate::service::Service;

impl From<Protocol> for firewall::Protocol {
    fn from(protocol: Protocol) -> Self {
        match protocol {
            Protocol::Tcp => Self::Tcp,
            Protocol::Udp => Self::Udp,
        }
    }
}

impl From<Ports> for firewall::Ports {
    fn from(ports: Ports) -> Self {
        Self {
            protocol: firewall::Protocol::from(ports.protocol()).into(),
            first: ports.first().get().into(),
            last: ports.last().get().into(),
        }
    }
}

impl TryFrom<firewall::Ports> for Ports {
    type Error = InvalidMessage;

    fn try_from(message: firewall::Ports) -> Result<Self, InvalidMessage> {
        let protocol = match firewall::Protocol::try_from(message.protocol) {
            Ok(firewall::Protocol::Tcp) => Protocol::Tcp,
            Ok(firewall::Protocol::Udp) => Protocol::Udp,
            Ok(firewall::Protocol::Unspecified) | Err(_) => {
                return Err(InvalidMessage::new("protocol", "must be tcp or udp"));
            }
        };
        let first = Port::try_from(message.first).field("first")?;
        let last = Port::try_from(message.last).field("last")?;
        Ports::new(protocol, first, last).field("last")
    }
}

impl From<Allowed> for firewall::Allowed {
    fn from(allowed: Allowed) -> Self {
        use firewall::allowed::What;
        let what = match allowed {
            Allowed::Service(service) => What::Service(service.name().to_owned()),
            Allowed::Ports(ports) => What::Ports(ports.into()),
        };
        Self { what: Some(what) }
    }
}

impl TryFrom<firewall::Allowed> for Allowed {
    type Error = InvalidMessage;

    fn try_from(message: firewall::Allowed) -> Result<Self, InvalidMessage> {
        use firewall::allowed::What;
        match message.what {
            Some(What::Service(name)) => Ok(Self::Service(name.parse().field("service")?)),
            Some(What::Ports(ports)) => Ok(Self::Ports(Ports::try_from(ports).within("ports")?)),
            None => Err(InvalidMessage::whole("a service or ports is required")),
        }
    }
}

/// The allowed list of a message's `field`.
fn allowed_list(items: Vec<firewall::Allowed>, field: &str) -> Result<AllowedList, InvalidMessage> {
    let items = (items.into_iter().enumerate())
        .map(|(i, item)| Allowed::try_from(item).within(&format!("{field}[{i}]")))
        .collect::<Result<Vec<_>, _>>()?;
    AllowedList::try_from(items).field(field)
}

impl From<&FirewallConfig> for firewall::Config {
    fn from(config: &FirewallConfig) -> Self {
        let items = |list: &AllowedList| list.items().iter().copied().map(Into::into).collect();
        Self {
            enabled: config.enabled,
            inbound: match config.inbound {
                Inbound::Drop => firewall::Inbound::Drop,
                Inbound::Reject => firewall::Inbound::Reject,
                Inbound::Accept => firewall::Inbound::Accept,
            }
            .into(),
            allowed_inbound: items(&config.allowed_inbound),
            outbound: match config.outbound {
                Outbound::Accept => firewall::Outbound::Accept,
                Outbound::Drop => firewall::Outbound::Drop,
            }
            .into(),
            allowed_outbound: items(&config.allowed_outbound),
            ping: config.ping,
            log_drops: config.log_drops,
        }
    }
}

impl TryFrom<firewall::Config> for FirewallConfig {
    type Error = InvalidMessage;

    fn try_from(message: firewall::Config) -> Result<Self, InvalidMessage> {
        let inbound = match firewall::Inbound::try_from(message.inbound) {
            Ok(firewall::Inbound::Drop) => Inbound::Drop,
            Ok(firewall::Inbound::Reject) => Inbound::Reject,
            Ok(firewall::Inbound::Accept) => Inbound::Accept,
            Ok(firewall::Inbound::Unspecified) | Err(_) => {
                return Err(InvalidMessage::new(
                    "inbound",
                    "must be drop, reject or accept",
                ));
            }
        };
        let outbound = match firewall::Outbound::try_from(message.outbound) {
            Ok(firewall::Outbound::Accept) => Outbound::Accept,
            Ok(firewall::Outbound::Drop) => Outbound::Drop,
            Ok(firewall::Outbound::Unspecified) | Err(_) => {
                return Err(InvalidMessage::new("outbound", "must be accept or drop"));
            }
        };
        Ok(Self {
            enabled: message.enabled,
            inbound,
            allowed_inbound: allowed_list(message.allowed_inbound, "allowed_inbound")?,
            outbound,
            allowed_outbound: allowed_list(message.allowed_outbound, "allowed_outbound")?,
            ping: message.ping,
            log_drops: message.log_drops,
        })
    }
}

impl From<Service> for firewall::Service {
    fn from(service: Service) -> Self {
        let info = service.info();
        Self {
            name: info.name.to_owned(),
            description: info.description.to_owned(),
            ports: info.ports.iter().copied().map(Into::into).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> FirewallConfig {
        FirewallConfig {
            inbound: Inbound::Reject,
            allowed_inbound: AllowedList::try_from(vec![
                "ssh".parse().unwrap(),
                "6000-6010/udp".parse().unwrap(),
            ])
            .unwrap(),
            outbound: Outbound::Drop,
            allowed_outbound: AllowedList::try_from(vec!["dns".parse().unwrap()]).unwrap(),
            ping: true,
            ..FirewallConfig::default()
        }
    }

    #[test]
    fn round_trips() {
        let config = config();
        let message = firewall::Config::from(&config);
        assert_eq!(FirewallConfig::try_from(message).unwrap(), config);
    }

    #[test]
    fn rejects_invalid_messages() {
        let valid = firewall::Config::from(&config());
        let ports = |protocol: firewall::Protocol, first, last| firewall::Allowed {
            what: Some(firewall::allowed::What::Ports(firewall::Ports {
                protocol: protocol.into(),
                first,
                last,
            })),
        };
        let with_inbound = |items: Vec<firewall::Allowed>| firewall::Config {
            allowed_inbound: items,
            ..valid.clone()
        };
        let service = |name: &str| firewall::Allowed {
            what: Some(firewall::allowed::What::Service(name.into())),
        };
        let no_inbound = firewall::Config {
            inbound: 0,
            ..valid.clone()
        };
        let unknown_outbound = firewall::Config {
            outbound: 7,
            ..valid.clone()
        };
        for (message, field) in [
            (no_inbound, "inbound"),
            (unknown_outbound, "outbound"),
            (
                with_inbound(vec![service("telnet")]),
                "allowed_inbound[0].service",
            ),
            (
                with_inbound(vec![ports(firewall::Protocol::Tcp, 0, 1)]),
                "allowed_inbound[0].ports.first",
            ),
            (
                with_inbound(vec![ports(firewall::Protocol::Udp, 10, 5)]),
                "allowed_inbound[0].ports.last",
            ),
            (
                with_inbound(vec![ports(firewall::Protocol::Unspecified, 1, 1)]),
                "allowed_inbound[0].ports.protocol",
            ),
            (
                with_inbound(vec![firewall::Allowed { what: None }]),
                "allowed_inbound[0]",
            ),
            (
                with_inbound(vec![service("ssh"), service("ssh")]),
                "allowed_inbound",
            ),
        ] {
            let error = FirewallConfig::try_from(message).unwrap_err();
            assert_eq!(error.field(), field, "{error}");
        }
    }
}

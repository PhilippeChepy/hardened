//! The time servers as time-controller's configuration.

use controllers_helpers::InvalidMessage;
use controllers_helpers::NonEmpty;
use controllers_helpers::invalid_message;

use crate::time;
use crate::{TimeConfig, TimeOrigin, TimeServer};

impl From<TimeOrigin> for time::Origin {
    fn from(origin: TimeOrigin) -> Self {
        match origin {
            TimeOrigin::Settings => Self::Settings,
            TimeOrigin::Dhcp => Self::Dhcp,
            TimeOrigin::Default => Self::Default,
        }
    }
}

impl From<TimeConfig> for time::Configuration {
    fn from(config: TimeConfig) -> Self {
        Self {
            servers: config.servers.into_iter().map(String::from).collect(),
            origin: time::Origin::from(config.origin).into(),
        }
    }
}

impl TryFrom<time::Configuration> for TimeConfig {
    type Error = InvalidMessage;

    fn try_from(message: time::Configuration) -> Result<Self, Self::Error> {
        let servers =
            invalid_message::convert_each(message.servers, "servers", TimeServer::try_from)?;
        let servers = NonEmpty::from_vec(servers)
            .ok_or_else(|| InvalidMessage::new("servers", "at least one is required"))?;
        let origin = match time::Origin::try_from(message.origin) {
            Ok(time::Origin::Settings) => TimeOrigin::Settings,
            Ok(time::Origin::Dhcp) => TimeOrigin::Dhcp,
            Ok(time::Origin::Default) => TimeOrigin::Default,
            Ok(time::Origin::Unspecified) | Err(_) => {
                return Err(InvalidMessage::new("origin", "must be set"));
            }
        };
        Ok(Self { servers, origin })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for origin in [TimeOrigin::Settings, TimeOrigin::Dhcp, TimeOrigin::Default] {
            let config = TimeConfig {
                servers: NonEmpty::from_vec(vec![
                    "time.example.com".parse().unwrap(),
                    "192.0.2.123".parse().unwrap(),
                ])
                .unwrap(),
                origin,
            };
            let message = time::Configuration::from(config.clone());
            assert_eq!(TimeConfig::try_from(message).unwrap(), config);
        }
    }

    #[test]
    fn rejects_invalid_configurations() {
        let valid = time::Configuration {
            servers: vec!["time.example.com".to_owned()],
            origin: time::Origin::Dhcp.into(),
        };
        for (message, field) in [
            (
                time::Configuration {
                    servers: Vec::new(),
                    ..valid.clone()
                },
                "servers",
            ),
            (
                time::Configuration {
                    servers: vec!["time.example.com".to_owned(), "ntp://x".to_owned()],
                    ..valid.clone()
                },
                "servers[1]",
            ),
            (
                time::Configuration {
                    origin: time::Origin::Unspecified.into(),
                    ..valid.clone()
                },
                "origin",
            ),
            (
                time::Configuration {
                    origin: 42,
                    ..valid.clone()
                },
                "origin",
            ),
        ] {
            assert_eq!(TimeConfig::try_from(message).unwrap_err().field(), field);
        }
    }
}

//! The firewall's configuration: on or off, and what it lets through.

use std::fmt;
use std::str::FromStr;

use serde::Deserialize;
use serde::Serialize;

use crate::ports::InvalidPorts;
use crate::ports::Ports;
use crate::service::Service;
use crate::service::UnknownService;

/// What a policy allows: a service by name, or ports. `ssh` or `8080/tcp` as text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allowed {
    /// A service's ports.
    Service(Service),
    /// Ports.
    Ports(Ports),
}

impl Allowed {
    /// The ports it opens.
    #[must_use]
    pub fn ports(&self) -> Vec<Ports> {
        match self {
            Self::Service(service) => service.info().ports.to_vec(),
            Self::Ports(ports) => vec![*ports],
        }
    }
}

impl fmt::Display for Allowed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Service(service) => service.fmt(f),
            Self::Ports(ports) => ports.fmt(f),
        }
    }
}

/// Why an allowed item is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidAllowed {
    /// Not a service's name.
    #[error(transparent)]
    Service(#[from] UnknownService),
    /// Invalid ports.
    #[error(transparent)]
    Ports(#[from] InvalidPorts),
}

impl FromStr for Allowed {
    type Err = InvalidAllowed;

    /// Ports have a `/`, services do not.
    fn from_str(text: &str) -> Result<Self, InvalidAllowed> {
        if text.contains('/') {
            Ok(Self::Ports(text.parse()?))
        } else {
            Ok(Self::Service(text.parse()?))
        }
    }
}

impl Serialize for Allowed {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Allowed {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// Why a list of allowed items is invalid.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InvalidAllowedList {
    /// More than [`AllowedList::MAX`].
    #[error("{0} items: at most {max}", max = AllowedList::MAX)]
    TooMany(usize),
    /// The same item twice.
    #[error("{0} is listed twice")]
    Duplicate(String),
}

/// What new connections may reach: at most [`Self::MAX`] items, each once, in order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Allowed>", into = "Vec<Allowed>")]
pub struct AllowedList(Vec<Allowed>);

impl AllowedList {
    /// The most items a list holds: each is a rule or two.
    pub const MAX: usize = 64;

    /// The items, in order.
    #[must_use]
    pub fn items(&self) -> &[Allowed] {
        &self.0
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<Vec<Allowed>> for AllowedList {
    type Error = InvalidAllowedList;

    fn try_from(items: Vec<Allowed>) -> Result<Self, InvalidAllowedList> {
        if items.len() > Self::MAX {
            return Err(InvalidAllowedList::TooMany(items.len()));
        }
        for (i, item) in items.iter().enumerate() {
            if items[..i].contains(item) {
                return Err(InvalidAllowedList::Duplicate(item.to_string()));
            }
        }
        Ok(Self(items))
    }
}

impl From<AllowedList> for Vec<Allowed> {
    fn from(list: AllowedList) -> Self {
        list.0
    }
}

/// What happens to new incoming connections not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Inbound {
    /// Dropped silently.
    Drop,
    /// Refused: a TCP reset, an ICMP port unreachable otherwise.
    Reject,
    /// Accepted.
    Accept,
}

/// What happens to new outgoing connections not allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outbound {
    /// Accepted.
    Accept,
    /// Dropped.
    Drop,
}

macro_rules! text_enum {
    ($type:ty, $what:literal, $($variant:ident => $text:literal),+ $(,)?) => {
        impl $type {
            /// Its name, as the command line and the porcelain write it.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $text,)+
                }
            }
        }

        impl fmt::Display for $type {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(self.name())
            }
        }

        impl FromStr for $type {
            type Err = String;

            fn from_str(text: &str) -> Result<Self, String> {
                match text {
                    $($text => Ok(Self::$variant),)+
                    _ => Err(format!(
                        concat!("{:?} is not ", $what, ": {}"),
                        text,
                        [$($text),+].join(", ")
                    )),
                }
            }
        }
    };
}

text_enum!(Inbound, "an inbound policy", Drop => "drop", Reject => "reject", Accept => "accept");
text_enum!(Outbound, "an outbound policy", Accept => "accept", Drop => "drop");

/// The firewall's configuration: what it lets through, besides what always goes through
/// (loopback, replies, DHCP's, IPv6's neighbour discovery). A key left out has its
/// [`Default`]'s value, but `enabled`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FirewallConfig {
    /// Off: nothing is filtered.
    pub enabled: bool,
    /// New incoming connections not allowed.
    #[serde(default = "default_inbound")]
    pub inbound: Inbound,
    /// What new incoming connections may reach.
    #[serde(default)]
    pub allowed_inbound: AllowedList,
    /// New outgoing connections not allowed.
    #[serde(default = "default_outbound")]
    pub outbound: Outbound,
    /// Where new outgoing connections may go, with [`Outbound::Drop`].
    #[serde(default)]
    pub allowed_outbound: AllowedList,
    /// Answer pings.
    #[serde(default)]
    pub ping: bool,
    /// Log what is blocked.
    #[serde(default = "default_log_drops")]
    pub log_drops: bool,
}

fn default_inbound() -> Inbound {
    Inbound::Drop
}

fn default_outbound() -> Outbound {
    Outbound::Accept
}

fn default_log_drops() -> bool {
    true
}

impl Default for FirewallConfig {
    /// On: nothing comes in but replies, DHCP's and IPv6's neighbour and router discovery, and
    /// what is blocked is logged. Applied at the first boot, before any configuration is kept.
    fn default() -> Self {
        Self {
            enabled: true,
            inbound: default_inbound(),
            allowed_inbound: AllowedList::default(),
            outbound: default_outbound(),
            allowed_outbound: AllowedList::default(),
            ping: false,
            log_drops: default_log_drops(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowed_round_trips() {
        for text in ["ssh", "8080/tcp", "6000-6010/udp"] {
            assert_eq!(text.parse::<Allowed>().unwrap().to_string(), text);
        }
        assert!(matches!(
            "mdns".parse::<Allowed>(),
            Err(InvalidAllowed::Service(_))
        ));
        assert!(matches!(
            "0/tcp".parse::<Allowed>(),
            Err(InvalidAllowed::Ports(_))
        ));
        let https: Allowed = "https".parse().unwrap();
        assert_eq!(
            https.ports(),
            ["443/tcp".parse().unwrap(), "443/udp".parse().unwrap()]
        );
    }

    #[test]
    fn lists_are_bounded_without_duplicates() {
        let item = |text: &str| text.parse::<Allowed>().unwrap();
        assert!(AllowedList::try_from(vec![item("ssh"), item("22/tcp")]).is_ok());
        assert_eq!(
            AllowedList::try_from(vec![item("ssh"), item("http"), item("ssh")]),
            Err(InvalidAllowedList::Duplicate("ssh".into()))
        );
        let many: Vec<_> = (1..=65).map(|port| item(&format!("{port}/tcp"))).collect();
        assert_eq!(
            AllowedList::try_from(many.clone()),
            Err(InvalidAllowedList::TooMany(65))
        );
        assert!(AllowedList::try_from(many[..64].to_vec()).is_ok());
    }

    #[test]
    fn names_round_trip() {
        for inbound in [Inbound::Drop, Inbound::Reject, Inbound::Accept] {
            assert_eq!(inbound.name().parse::<Inbound>(), Ok(inbound));
        }
        for outbound in [Outbound::Accept, Outbound::Drop] {
            assert_eq!(outbound.name().parse::<Outbound>(), Ok(outbound));
        }
        assert_eq!(
            "reset".parse::<Inbound>(),
            Err(r#""reset" is not an inbound policy: drop, reject, accept"#.to_owned())
        );
    }

    #[test]
    fn json_round_trips_and_validates() {
        let mut config = FirewallConfig::default();
        assert!(config.enabled, "on by default");
        config.allowed_inbound =
            AllowedList::try_from(vec!["ssh".parse().unwrap(), "8080/tcp".parse().unwrap()])
                .unwrap();
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serde_json::from_str::<FirewallConfig>(&json).unwrap(),
            config
        );
        assert!(
            json.contains(r#""allowed-inbound":["ssh","8080/tcp"]"#),
            "{json}"
        );

        // The keys but `enabled` may be left out: the defaults.
        let minimal: FirewallConfig = serde_json::from_str(r#"{"enabled": false}"#).unwrap();
        assert_eq!(
            minimal,
            FirewallConfig {
                enabled: false,
                ..FirewallConfig::default()
            }
        );

        for invalid in [
            r#"{}"#,
            r#"{"enabled": true, "inbound": "reset"}"#,
            r#"{"enabled": true, "x": 1}"#,
            r#"{"enabled": true, "allowed-inbound": ["telnet"]}"#,
            r#"{"enabled": true, "allowed-inbound": ["ssh", "ssh"]}"#,
        ] {
            assert!(
                serde_json::from_str::<FirewallConfig>(invalid).is_err(),
                "{invalid}"
            );
        }
    }
}

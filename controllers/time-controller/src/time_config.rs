//! What time-controller synchronizes with.

use controllers_helpers::NonEmpty;
use serde::Deserialize;
use serde::Serialize;

use crate::TimeServer;

/// What time-controller synchronizes the clock with: the hypervisor's PTP clock or the time
/// servers, as `source` says; the servers chosen by machine-controller from the settings, DHCP
/// or the default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TimeConfig {
    /// In order of preference.
    pub servers: NonEmpty<TimeServer>,
    /// Where they come from.
    pub origin: TimeOrigin,
    /// What the clock is synchronized with.
    #[serde(default)]
    pub source: TimeSource,
}

/// What the clock is synchronized with: `settings.hardened.time.source`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimeSource {
    /// The hypervisor's PTP clock (KVM's) when there is one, NTP otherwise or when it fails.
    #[default]
    Auto,
    /// The hypervisor's PTP clock only.
    Ptp,
    /// The time servers only.
    Ntp,
}

/// Where the time servers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TimeOrigin {
    /// `settings.ntp.time-servers`.
    Settings,
    /// DHCP (option 42).
    Dhcp,
    /// The default: `pool.ntp.org`.
    Default,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialization_rejects_no_servers() {
        let config: TimeConfig =
            serde_json::from_str(r#"{"servers": ["192.0.2.123"], "origin": "dhcp"}"#).unwrap();
        assert_eq!(config.servers.first().to_string(), "192.0.2.123");
        assert!(
            serde_json::from_str::<TimeConfig>(r#"{"servers": [], "origin": "dhcp"}"#).is_err()
        );
    }
}

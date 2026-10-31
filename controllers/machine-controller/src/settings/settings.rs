//! The root of the settings, and its groups too small for a module of their own.

use std::collections::BTreeMap;

use controllers_helpers::{Hostname, WorkloadName};
use kubelet_controller::KubeletConfig;
use machine_apiproxy::ApiConfig;
use network_controller::DnsSettings;
use serde::{Deserialize, Serialize};
use storage_controller::StorageSettings;
use time_controller::TimeServer;
use time_controller::TimeSource;
use workload_controller::ContainerSettings;

use crate::settings::{KernelSettings, RegistrySettings};

/// The settings (`[settings]` of user-data): Bottlerocket's groups where it has them (with its
/// keys), hardened's own under `hardened`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Settings {
    /// `[settings.kernel]`.
    #[serde(default)]
    pub kernel: KernelSettings,
    /// `[settings.network]`.
    #[serde(default)]
    pub network: NetworkSettings,
    /// `[settings.dns]`.
    #[serde(default)]
    pub dns: DnsSettings,
    /// `[settings.ntp]`.
    #[serde(default)]
    pub ntp: NtpSettings,
    /// `[settings.kubernetes]`: kubelet runs when it is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kubernetes: Option<KubeletConfig>,
    /// `[settings.container-registry]`.
    #[serde(default)]
    pub container_registry: RegistrySettings,
    /// `[settings.hardened]`.
    #[serde(default)]
    pub hardened: HardenedSettings,
}

/// `[settings.network]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NetworkSettings {
    /// Overrides the platform's hostname.
    pub hostname: Option<Hostname>,
}

/// `[settings.ntp]`: time synchronization.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NtpSettings {
    /// The servers, in order of preference. When empty, those of DHCP (option 42), or else
    /// `pool.ntp.org`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub time_servers: Vec<TimeServer>,
}

/// `[settings.hardened]`: what Bottlerocket has no setting for.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HardenedSettings {
    /// `[settings.hardened.api]`: the API, served by machine-apiproxy when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ApiConfig>,
    /// `[settings.hardened.storage]`: the state partition.
    #[serde(default)]
    pub storage: StorageSettings,
    /// `[settings.hardened.time]`.
    #[serde(default)]
    pub time: TimeSettings,
    /// `[settings.hardened.containers.<name>]`: containers, keyed by name; the API's run next to
    /// them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub containers: BTreeMap<WorkloadName, ContainerSettings>,
}

/// `[settings.hardened.time]`: what the clock is synchronized with.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TimeSettings {
    /// The hypervisor's PTP clock, the time servers of `[settings.ntp]`, or the first falling
    /// back to the second (the default).
    #[serde(default)]
    pub source: TimeSource,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::settings_message::tests::full_settings;

    #[test]
    fn empty_settings_are_the_defaults() {
        assert_eq!(toml::from_str::<Settings>("").unwrap(), Settings::default());
    }

    #[test]
    fn round_trips_with_the_secrets() {
        let settings = full_settings();
        let text = toml::to_string(&settings).unwrap();
        assert_eq!(toml::from_str::<Settings>(&text).unwrap(), settings);
        let json = serde_json::to_string(&settings).unwrap();
        assert_eq!(serde_json::from_str::<Settings>(&json).unwrap(), settings);
        assert!(json.contains("hunter2"), "{json}");
    }

    #[test]
    fn rejects_unknown_keys() {
        for (document, why) in [
            ("[hots]\nhostname = \"x\"\n", "an unknown table"),
            ("[network]\nhost-name = \"x\"\n", "an unknown key"),
            ("[dns]\nname_servers = []\n", "a snake_case key"),
        ] {
            assert!(
                toml::from_str::<Settings>(document).is_err(),
                "{why} accepted"
            );
        }
    }
}

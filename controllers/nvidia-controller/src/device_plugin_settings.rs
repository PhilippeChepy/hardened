//! `[settings.kubelet-device-plugins.nvidia]`: NVIDIA's device plugin, with Bottlerocket's keys
//! and values.
//!
//! The plugin hands kubelet's containers their GPUs through CDI (containerd reads the specs it
//! writes): Bottlerocket's `volume-mounts` and `envvar` list strategies, which go through NVIDIA's
//! container runtime there, stand for CDI here, the containers getting the same devices and
//! libraries. MIG partitioning is nvidia-controller's, which lays the GPUs out before the plugin
//! starts. MPS sharing, which needs a daemon of its own, is not supported yet: its table is
//! accepted, as Bottlerocket accepts it, but choosing it is an error.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

/// `[settings.kubelet-device-plugins.nvidia]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Keys", into = "Keys")]
pub struct DevicePluginSettings {
    /// Whether the plugin runs (on a node with NVIDIA GPUs, under kubelet).
    pub enabled: bool,
    /// Gives containers the GPUs' device nodes in their specs.
    pub pass_device_specs: bool,
    /// How containers name their GPUs.
    pub device_id_strategy: DeviceIdStrategy,
    /// How the runtime learns a container's GPUs, as written (one value or several): CDI here.
    pub device_list_strategy: Vec<DeviceListStrategy>,
    /// How GPUs are shared between containers.
    pub device_sharing_strategy: DeviceSharingStrategy,
    /// The replicas of time-slicing.
    pub time_slicing: TimeSlicing,
    /// `[...nvidia.mps]`, kept as written: MPS sharing is not supported yet.
    pub mps: Option<Mps>,
    /// How GPUs are partitioned.
    pub device_partitioning_strategy: DevicePartitioningStrategy,
    /// `[...nvidia.mig]`: the GPUs' MIG profiles, when they are partitioned.
    pub mig: Option<Mig>,
}

impl DevicePluginSettings {
    /// The plugin's `--device-list-strategy`: CDI's strategies, those of `device-list-strategy`
    /// (`volume-mounts` and `envvar` being `cdi-cri`), comma-separated.
    #[must_use]
    pub fn plugin_list_strategy(&self) -> String {
        let mut strategies: Vec<&str> = Vec::new();
        for strategy in &self.device_list_strategy {
            let cdi = strategy.cdi();
            if !strategies.contains(&cdi) {
                strategies.push(cdi);
            }
        }
        strategies.join(",")
    }
}

impl Default for DevicePluginSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            pass_device_specs: true,
            device_id_strategy: DeviceIdStrategy::default(),
            device_list_strategy: vec![DeviceListStrategy::VolumeMounts],
            device_sharing_strategy: DeviceSharingStrategy::default(),
            time_slicing: TimeSlicing::default(),
            mps: None,
            device_partitioning_strategy: DevicePartitioningStrategy::default(),
            mig: None,
        }
    }
}

/// `device-id-strategy`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceIdStrategy {
    /// GPUs by index (`0`, `1`...).
    #[default]
    Index,
    /// GPUs by UUID.
    Uuid,
}

/// A value of `device-list-strategy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeviceListStrategy {
    /// Bottlerocket's default; CRI's CDI devices here.
    VolumeMounts,
    /// CRI's CDI devices here.
    Envvar,
    /// CRI's CDI devices field.
    CdiCri,
    /// CDI annotations on the container.
    CdiAnnotations,
}

impl DeviceListStrategy {
    /// The CDI strategy it stands for.
    #[must_use]
    fn cdi(self) -> &'static str {
        match self {
            Self::VolumeMounts | Self::Envvar | Self::CdiCri => "cdi-cri",
            Self::CdiAnnotations => "cdi-annotations",
        }
    }
}

/// `device-sharing-strategy`, as supported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeviceSharingStrategy {
    /// One container per GPU.
    #[default]
    None,
    /// Containers take turns on the GPUs (`time-slicing`).
    TimeSlicing,
}

/// `device-partitioning-strategy`, as supported.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DevicePartitioningStrategy {
    /// Whole GPUs.
    #[default]
    None,
    /// MIG instances, all of one profile on each GPU (the plugin's `single` strategy).
    Mig,
}

/// `[settings.kubelet-device-plugins.nvidia.time-slicing]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct TimeSlicing {
    /// How many containers share each GPU.
    #[serde(default = "two")]
    pub replicas: NonZeroU16,
    /// Advertises `nvidia.com/gpu.shared` rather than `nvidia.com/gpu`.
    #[serde(default)]
    pub rename_by_default: bool,
    /// Refuses requests of more than one shared GPU.
    #[serde(default)]
    pub fail_requests_greater_than_one: bool,
}

impl Default for TimeSlicing {
    fn default() -> Self {
        Self {
            replicas: two(),
            rename_by_default: false,
            fail_requests_greater_than_one: false,
        }
    }
}

/// `[settings.kubelet-device-plugins.nvidia.mps]`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Mps {
    /// How many containers would share each GPU.
    pub replicas: Option<NonZeroU16>,
}

/// `[settings.kubelet-device-plugins.nvidia.mig]`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Mig {
    /// The MIG profile of each GPU model (`"a100.40gb" = "1g.5gb"`), or its number of instances
    /// (`"a100.40gb" = "7"`); a model without one is a single instance of the whole GPU.
    #[serde(default)]
    pub profile: BTreeMap<GpuModel, MigProfile>,
}

/// A GPU model as Bottlerocket names it: `<name>.<memory>gb` (`a100.40gb`, `h200.141gb`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GpuModel {
    name: String,
    memory_gb: u32,
}

impl GpuModel {
    /// Its memory, in GB.
    #[must_use]
    pub fn memory_gb(&self) -> u32 {
        self.memory_gb
    }
}

impl TryFrom<String> for GpuModel {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let invalid = || format!("{text:?} is not a GPU model (<name>.<memory>gb, as a100.40gb)");
        let (name, memory) = text.split_once('.').ok_or_else(invalid)?;
        let memory_gb = gigabytes(memory).ok_or_else(invalid)?;
        let lowercase_alphanumeric = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit();
        if name.is_empty() || !name.chars().all(lowercase_alphanumeric) {
            return Err(invalid());
        }
        Ok(Self {
            name: name.to_owned(),
            memory_gb,
        })
    }
}

impl From<GpuModel> for String {
    fn from(model: GpuModel) -> Self {
        model.to_string()
    }
}

impl fmt::Display for GpuModel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}gb", self.name, self.memory_gb)
    }
}

/// A value of `mig.profile`: a MIG profile, or how many instances a GPU is split into.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum MigProfile {
    /// `<slices>g.<memory>gb` (`1g.5gb`): of the 7 compute slices, and memory in GB.
    Named {
        /// Its compute slices.
        slices: u8,
        /// Its memory, in GB.
        memory_gb: u32,
    },
    /// How many instances of the same profile.
    Instances(u8),
}

impl TryFrom<String> for MigProfile {
    type Error = String;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let invalid = || {
            format!(
                "{text:?} is not a MIG profile (<slices>g.<memory>gb, as 1g.5gb) \
                 or a number of instances (1 to 7)"
            )
        };
        if let Some((slices, memory)) = text.split_once("g.") {
            let slices = one_to_seven(slices).ok_or_else(invalid)?;
            let memory_gb = gigabytes(memory).ok_or_else(invalid)?;
            return Ok(Self::Named { slices, memory_gb });
        }
        one_to_seven(&text).map(Self::Instances).ok_or_else(invalid)
    }
}

impl From<MigProfile> for String {
    fn from(profile: MigProfile) -> Self {
        profile.to_string()
    }
}

impl fmt::Display for MigProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Named { slices, memory_gb } => write!(f, "{slices}g.{memory_gb}gb"),
            Self::Instances(instances) => write!(f, "{instances}"),
        }
    }
}

/// The GB of `<n>gb`.
#[must_use]
fn gigabytes(text: &str) -> Option<u32> {
    positive(text.strip_suffix("gb")?)
}

/// A one-digit count of slices or instances: a GPU has 7 compute slices.
#[must_use]
fn one_to_seven(text: &str) -> Option<u8> {
    positive(text)
        .filter(|n| *n <= 7)
        .and_then(|n| u8::try_from(n).ok())
}

/// A positive number in decimal digits, without sign or leading zero.
#[must_use]
fn positive(digits: &str) -> Option<u32> {
    if digits.starts_with('0') || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    digits.parse().ok()
}

fn yes() -> bool {
    true
}

fn two() -> NonZeroU16 {
    NonZeroU16::MIN.saturating_add(1)
}

/// The keys as Bottlerocket writes them, converted from and to [`DevicePluginSettings`].
#[derive(Deserialize, Serialize)]
#[serde(
    rename_all = "kebab-case",
    deny_unknown_fields,
    expecting = "the table of settings.kubelet-device-plugins.nvidia"
)]
struct Keys {
    #[serde(default = "yes")]
    enabled: bool,
    #[serde(default = "yes")]
    pass_device_specs: bool,
    #[serde(default)]
    device_id_strategy: DeviceIdStrategy,
    #[serde(default)]
    device_list_strategy: ListStrategies,
    #[serde(default)]
    device_sharing_strategy: Sharing,
    #[serde(default)]
    time_slicing: TimeSlicing,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mps: Option<Mps>,
    #[serde(default)]
    device_partitioning_strategy: Partitioning,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    mig: Option<Mig>,
}

/// `device-list-strategy`: one value, or several.
#[derive(Deserialize, Serialize)]
#[serde(untagged, expecting = "a device list strategy, or a list of them")]
enum ListStrategies {
    One(DeviceListStrategy),
    Many(Vec<DeviceListStrategy>),
}

impl Default for ListStrategies {
    fn default() -> Self {
        Self::One(DeviceListStrategy::VolumeMounts)
    }
}

/// `device-sharing-strategy`, as Bottlerocket takes it.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Sharing {
    #[default]
    None,
    TimeSlicing,
    Mps,
}

/// `device-partitioning-strategy`, as Bottlerocket takes it.
#[derive(Debug, Clone, Copy, Default, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
enum Partitioning {
    #[default]
    None,
    Mig,
}

impl TryFrom<Keys> for DevicePluginSettings {
    type Error = String;

    fn try_from(keys: Keys) -> Result<Self, Self::Error> {
        let device_list_strategy = match keys.device_list_strategy {
            ListStrategies::One(strategy) => vec![strategy],
            ListStrategies::Many(strategies) if !strategies.is_empty() => strategies,
            ListStrategies::Many(_) => return Err("device-list-strategy is empty".to_owned()),
        };
        let device_sharing_strategy = match keys.device_sharing_strategy {
            Sharing::None => DeviceSharingStrategy::None,
            Sharing::TimeSlicing => DeviceSharingStrategy::TimeSlicing,
            Sharing::Mps => {
                return Err("device-sharing-strategy \"mps\" is not supported yet".to_owned());
            }
        };
        let device_partitioning_strategy = match keys.device_partitioning_strategy {
            Partitioning::None => DevicePartitioningStrategy::None,
            Partitioning::Mig => DevicePartitioningStrategy::Mig,
        };
        Ok(Self {
            enabled: keys.enabled,
            pass_device_specs: keys.pass_device_specs,
            device_id_strategy: keys.device_id_strategy,
            device_list_strategy,
            device_sharing_strategy,
            time_slicing: keys.time_slicing,
            mps: keys.mps,
            device_partitioning_strategy,
            mig: keys.mig,
        })
    }
}

impl From<DevicePluginSettings> for Keys {
    fn from(settings: DevicePluginSettings) -> Self {
        let device_list_strategy =
            match <[DeviceListStrategy; 1]>::try_from(settings.device_list_strategy) {
                Ok([strategy]) => ListStrategies::One(strategy),
                Err(strategies) => ListStrategies::Many(strategies),
            };
        Self {
            enabled: settings.enabled,
            pass_device_specs: settings.pass_device_specs,
            device_id_strategy: settings.device_id_strategy,
            device_list_strategy,
            device_sharing_strategy: match settings.device_sharing_strategy {
                DeviceSharingStrategy::None => Sharing::None,
                DeviceSharingStrategy::TimeSlicing => Sharing::TimeSlicing,
            },
            time_slicing: settings.time_slicing,
            mps: settings.mps,
            device_partitioning_strategy: match settings.device_partitioning_strategy {
                DevicePartitioningStrategy::None => Partitioning::None,
                DevicePartitioningStrategy::Mig => Partitioning::Mig,
            },
            mig: settings.mig,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<DevicePluginSettings, toml::de::Error> {
        toml::from_str(text)
    }

    #[test]
    fn bottlerocket_s_keys_and_defaults() {
        assert_eq!(parse("").unwrap(), DevicePluginSettings::default());
        let settings = parse(
            "device-id-strategy = \"uuid\"\ndevice-sharing-strategy = \"time-slicing\"\n\
             time-slicing.replicas = 4\ntime-slicing.rename-by-default = true\n",
        )
        .unwrap();
        assert_eq!(settings.device_id_strategy, DeviceIdStrategy::Uuid);
        assert_eq!(settings.time_slicing.replicas.get(), 4);
        assert!(settings.time_slicing.rename_by_default);
        for unsupported in [
            "device-sharing-strategy = \"mps\"",
            "device-list-strategy = []",
            "time-slicing.replicas = 0",
        ] {
            assert!(parse(unsupported).is_err(), "{unsupported}");
        }
    }

    #[test]
    fn bottlerocket_s_documents_are_accepted() {
        // Bottlerocket's own example: both legacy list strategies, an unused MPS table, a MIG
        // table its partitioning strategy does not choose.
        let settings = parse(
            "pass-device-specs = true\ndevice-id-strategy = \"index\"\n\
             device-list-strategy = [\"volume-mounts\", \"envvar\"]\n\
             device-sharing-strategy = \"time-slicing\"\n\
             device-partitioning-strategy = \"none\"\n\
             [time-slicing]\nreplicas = 2\nrename-by-default = true\n\
             fail-requests-greater-than-one = true\n\
             [mps]\n\
             [mig.profile]\n\"a100.40gb\" = \"1g.5gb\"\n",
        )
        .unwrap();
        assert_eq!(settings.plugin_list_strategy(), "cdi-cri");
        assert_eq!(settings.mps, Some(Mps { replicas: None }));
        let a100 = GpuModel::try_from("a100.40gb".to_owned()).unwrap();
        assert_eq!(
            settings.mig.as_ref().unwrap().profile[&a100],
            MigProfile::Named {
                slices: 1,
                memory_gb: 5
            }
        );
        let text = toml::to_string(&settings).unwrap();
        assert_eq!(parse(&text).unwrap(), settings, "round-trips:\n{text}");
    }

    #[test]
    fn cdi_strategies_for_the_plugin() {
        let strategies = |text: &str| parse(text).unwrap().plugin_list_strategy();
        assert_eq!(strategies(""), "cdi-cri");
        assert_eq!(strategies("device-list-strategy = \"envvar\""), "cdi-cri");
        assert_eq!(
            strategies("device-list-strategy = [\"cdi-annotations\", \"volume-mounts\"]"),
            "cdi-annotations,cdi-cri"
        );
    }

    #[test]
    fn mig_partitioning_with_bottlerocket_s_profiles() {
        let settings = parse(
            "device-partitioning-strategy = \"mig\"\n[mig.profile]\n\
             \"a100.40gb\" = \"2g.10gb\"\n\"h100.80gb\" = \"4\"\n\"b300.269gb\" = \"7g.269gb\"\n",
        )
        .unwrap();
        assert_eq!(
            settings.device_partitioning_strategy,
            DevicePartitioningStrategy::Mig
        );
        let profile = &settings.mig.as_ref().unwrap().profile;
        let h100 = GpuModel::try_from("h100.80gb".to_owned()).unwrap();
        assert_eq!(h100.memory_gb(), 80);
        assert_eq!(profile[&h100], MigProfile::Instances(4));
        let text = toml::to_string(&settings).unwrap();
        assert_eq!(parse(&text).unwrap(), settings, "round-trips:\n{text}");
        // Without a profile: one instance of each whole GPU.
        let settings = parse("device-partitioning-strategy = \"mig\"").unwrap();
        assert_eq!(settings.mig, None);
    }

    #[test]
    fn mig_profiles_and_models_are_checked() {
        for invalid in [
            "\"a100.40gb\" = \"0\"",
            "\"a100.40gb\" = \"8\"",
            "\"a100.40gb\" = \"+2\"",
            "\"a100.40gb\" = \"8g.5gb\"",
            "\"a100.40gb\" = \"1g.05gb\"",
            "\"a100.40gb\" = \"1g.5\"",
            "\"a100.40gb\" = \"1g.5gb+me\"",
            "\"a100\" = \"1g.5gb\"",
            "\"A100.40gb\" = \"1g.5gb\"",
            "\".40gb\" = \"1g.5gb\"",
        ] {
            assert!(
                parse(&format!("[mig.profile]\n{invalid}")).is_err(),
                "{invalid}"
            );
        }
    }
}

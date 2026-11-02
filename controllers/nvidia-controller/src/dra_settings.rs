//! `[settings.hardened.nvidia-dra]`: NVIDIA's DRA driver, its kubelet plugin on the node.

use serde::{Deserialize, Serialize};

/// `[settings.hardened.nvidia-dra]`. Off by default: with the device plugin, both would advertise
/// the same GPUs. The cluster deploys the driver's controller and device classes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DraSettings {
    /// Whether the kubelet plugin runs (on a node with NVIDIA GPUs, under kubelet).
    #[serde(default)]
    pub enabled: bool,
}

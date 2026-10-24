//! State shared by the boot sequence and the control API.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::SystemTime;

use tokio::sync::mpsc;

use crate::attestation::Tpm;
use crate::logging::LogRing;
use crate::platform::Platform;
use crate::settings::Settings;
use crate::types::Hostname;
use crate::workloads::Manager;

/// Identity of the running machine, fixed once booted.
#[derive(Debug, Clone)]
pub struct MachineInfo {
    pub os_name: &'static str,
    pub os_version: String,
    pub kernel: String,
    /// `None` when no metadata source was detected.
    pub platform: Option<Platform>,
    pub instance_id: Option<String>,
    pub hostname: Hostname,
    /// `None` if the kernel did not provide one.
    pub boot_id: Option<uuid::Uuid>,
    pub booted_at: SystemTime,
}

/// A power state change requested through the API or by the platform (ACPI power button).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerRequest {
    Reboot,
    PowerOff,
}

pub struct Machine {
    pub info: MachineInfo,
    /// Settings from user-data, fixed for the life of the boot. Workloads applied through the
    /// API live in [`Manager`] only.
    pub settings: Settings,
    pub logs: LogRing,
    /// Set once containerd is connected. Until then (or if it never connects), the workload
    /// calls of the API are unavailable; the rest of the API works, to diagnose it remotely.
    pub workloads: OnceLock<Arc<Manager>>,
    /// The TPM, if the machine has one. Blocking: use from `spawn_blocking`.
    pub tpm: Option<Arc<Mutex<Tpm>>>,
    pub power: mpsc::Sender<PowerRequest>,
}

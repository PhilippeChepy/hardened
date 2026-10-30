//! What the machine is, fixed for the boot: `hardened.machine.v1.Machine.Version`.

use std::fs;
use std::time::Duration;
use std::time::SystemTime;

use controllers_helpers::Hostname;
use machine_controller::machine::VersionResponse;
use rustix::time::ClockId;
use serde::Deserialize;
use serde::Serialize;

use crate::metadata::Platform;

const OS_NAME: &str = "hardened";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct MachineIdentity {
    /// `VERSION_ID` of `/usr/lib/os-release`.
    pub os_version: String,
    /// The kernel release.
    pub kernel: String,
    /// `None` when no metadata source was detected.
    pub platform: Option<Platform>,
    /// The platform's ID of the instance, when its metadata has one.
    pub instance_id: Option<String>,
    pub hostname: Hostname,
    /// The kernel's random boot ID.
    pub boot_id: Option<String>,
    /// When the machine booted (the wall clock less `CLOCK_BOOTTIME`), in milliseconds since the
    /// Unix epoch.
    pub booted_at_unix_ms: u64,
}

impl MachineIdentity {
    /// This machine's, with what the setup found.
    #[must_use]
    pub fn read(
        platform: Option<Platform>,
        instance_id: Option<String>,
        hostname: Hostname,
    ) -> Self {
        Self {
            os_version: os_release_field("VERSION_ID").unwrap_or_else(|| "unknown".to_owned()),
            kernel: kernel_release(),
            platform,
            instance_id,
            hostname,
            boot_id: fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .map(|id| id.trim().to_owned()),
            booted_at_unix_ms: booted_at_unix_ms(),
        }
    }

    /// The answer of `Machine.Version`.
    #[must_use]
    pub fn to_version(&self) -> VersionResponse {
        let booted_at = SystemTime::UNIX_EPOCH + Duration::from_millis(self.booted_at_unix_ms);
        VersionResponse {
            os_name: OS_NAME.to_owned(),
            os_version: self.os_version.clone(),
            kernel: self.kernel.clone(),
            platform: self
                .platform
                .map(Platform::name)
                .unwrap_or_default()
                .to_owned(),
            instance_id: self.instance_id.clone().unwrap_or_default(),
            hostname: self.hostname.to_string(),
            boot_id: self.boot_id.clone().unwrap_or_default(),
            booted_at: Some(booted_at.into()),
        }
    }
}

/// The running kernel's release.
#[must_use]
pub fn kernel_release() -> String {
    rustix::system::uname()
        .release()
        .to_string_lossy()
        .into_owned()
}

/// When the machine booted: the time now, less the time since boot (suspend included).
#[must_use]
fn booted_at_unix_ms() -> u64 {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let uptime = rustix::time::clock_gettime(ClockId::Boottime);
    let uptime = Duration::new(
        u64::try_from(uptime.tv_sec).unwrap_or_default(),
        u32::try_from(uptime.tv_nsec).unwrap_or_default(),
    );
    now.saturating_sub(uptime)
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// The value of `key` in `/usr/lib/os-release`, unquoted.
#[must_use]
fn os_release_field(key: &str) -> Option<String> {
    let text = fs::read_to_string("/usr/lib/os-release").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(|value| value.trim_matches('"').to_owned())
}

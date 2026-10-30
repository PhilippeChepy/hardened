//! The platform, detected from SMBIOS/DMI strings or the `hardened.platform=<name>` kernel
//! parameter, and its instance metadata.

use std::fmt;
use std::fs;
use std::path::Path;

use controllers_helpers::Hostname;
use serde::Deserialize;
use serde::Serialize;

use crate::metadata::exoscale;
use crate::metadata::qemu;

/// What the platform tells about the instance; all of it optional.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    pub instance_id: Option<String>,
    pub hostname: Option<Hostname>,
    /// Still in its transport encoding (gzip, base64).
    pub user_data: Option<Vec<u8>>,
}

/// A platform machine-controller knows the metadata service of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Platform {
    /// Local qemu: user-data from the `opt/hardened/user-data` fw_cfg entry.
    Qemu,
    /// Exoscale: an EC2-style metadata service.
    Exoscale,
}

impl Platform {
    /// Its name, as `hardened.platform=` takes it.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Qemu => "qemu",
            Self::Exoscale => "exoscale",
        }
    }

    /// From the kernel command line, else SMBIOS/DMI.
    #[must_use]
    pub fn detect() -> Option<Self> {
        let cmdline = fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if let Some(name) = cmdline
            .split_ascii_whitespace()
            .find_map(|arg| arg.strip_prefix("hardened.platform="))
        {
            return [Self::Qemu, Self::Exoscale]
                .into_iter()
                .find(|platform| platform.name() == name);
        }
        Self::from_dmi(&Dmi::read(Path::new("/sys/class/dmi/id")))
    }

    #[must_use]
    fn from_dmi(dmi: &Dmi) -> Option<Self> {
        let has = |field: &str, needle: &str| field.to_ascii_lowercase().contains(needle);
        if has(&dmi.sys_vendor, "exoscale") || has(&dmi.product_name, "exoscale") {
            Some(Self::Exoscale)
        } else if has(&dmi.sys_vendor, "qemu") || Path::new(qemu::FW_CFG_USER_DATA).exists() {
            Some(Self::Qemu)
        } else {
            None
        }
    }

    /// Fetches the instance's metadata from the platform's service.
    pub async fn fetch(self) -> anyhow::Result<Metadata> {
        match self {
            Self::Qemu => qemu::fetch().await,
            Self::Exoscale => exoscale::fetch().await,
        }
    }
}

impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// SMBIOS strings, from sysfs.
struct Dmi {
    sys_vendor: String,
    product_name: String,
}

impl Dmi {
    fn read(dir: &Path) -> Self {
        let field = |name: &str| {
            fs::read_to_string(dir.join(name))
                .map(|value| value.trim().to_owned())
                .unwrap_or_default()
        };
        Self {
            sys_vendor: field("sys_vendor"),
            product_name: field("product_name"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dmi(sys_vendor: &str, product_name: &str) -> Dmi {
        Dmi {
            sys_vendor: sys_vendor.into(),
            product_name: product_name.into(),
        }
    }

    #[test]
    fn detects_platforms_from_dmi() {
        assert_eq!(
            Platform::from_dmi(&dmi("Exoscale", "Exoscale Compute Platform")),
            Some(Platform::Exoscale)
        );
        assert_eq!(
            Platform::from_dmi(&dmi("QEMU", "Standard PC (Q35 + ICH9, 2009)")),
            Some(Platform::Qemu)
        );
        assert_eq!(Platform::from_dmi(&dmi("Amazon EC2", "m7i.large")), None);
    }

    #[test]
    fn reads_dmi_from_sysfs_layout() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("sys_vendor"), "Exoscale\n").unwrap();
        std::fs::write(
            dir.path().join("product_name"),
            "Exoscale Compute Platform\n",
        )
        .unwrap();
        let dmi = Dmi::read(dir.path());
        assert_eq!(dmi.sys_vendor, "Exoscale");
        assert_eq!(Platform::from_dmi(&dmi), Some(Platform::Exoscale));
    }
}

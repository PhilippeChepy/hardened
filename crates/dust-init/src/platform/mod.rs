//! Cloud platform detection and instance metadata.
//!
//! Each platform module exposes `async fn fetch() -> anyhow::Result<Metadata>`, a thin wrapper
//! around `fetch_from(&http::Client)` so providers can be tested against a local mock server.
//! Detection relies on SMBIOS/DMI strings, overridable with the `hardened.platform=<name>` kernel
//! parameter.

mod exoscale;
pub mod http;
mod qemu;

use std::fmt;
use std::path::Path;

use anyhow::Context as _;

use crate::types::Hostname;

/// Instance identity and configuration provided by the platform.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Metadata {
    pub instance_id: Option<String>,
    pub hostname: Option<Hostname>,
    pub region: Option<String>,
    pub zone: Option<String>,
    /// Raw user-data, still in its transport encoding (see [`crate::settings::decode`]).
    pub user_data: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// Local qemu: user-data from the `opt/hardened/user-data` fw_cfg entry.
    Qemu,
    Exoscale,
}

impl Platform {
    pub const ALL: [Self; 2] = [Self::Qemu, Self::Exoscale];

    pub fn name(self) -> &'static str {
        match self {
            Self::Qemu => "qemu",
            Self::Exoscale => "exoscale",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.name() == name)
    }

    /// Detects the platform from the kernel command line, then SMBIOS/DMI.
    pub fn detect() -> Option<Self> {
        let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
        if let Some(name) = cmdline
            .split_ascii_whitespace()
            .find_map(|arg| arg.strip_prefix("hardened.platform="))
        {
            return Self::from_name(name);
        }
        Self::from_dmi(&Dmi::read(Path::new("/sys/class/dmi/id")))
    }

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

    /// Fetches instance metadata and user-data.
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

/// SMBIOS strings exported by the kernel.
#[derive(Debug, Default)]
struct Dmi {
    sys_vendor: String,
    product_name: String,
}

impl Dmi {
    fn read(dir: &Path) -> Self {
        let field = |name: &str| {
            std::fs::read_to_string(dir.join(name))
                .map(|s| s.trim().to_owned())
                .unwrap_or_default()
        };
        Self {
            sys_vendor: field("sys_vendor"),
            product_name: field("product_name"),
        }
    }
}

/// Turns a platform-provided name into a hostname (see [`Hostname::sanitize`]).
fn sanitize_hostname(raw: &str) -> Option<Hostname> {
    Hostname::sanitize(raw)
}

/// GETs a metadata value as trimmed text; missing (404) and blank values are `None`.
async fn get_text(client: &http::Client, path: &str, headers: &[http::Header]) -> anyhow::Result<Option<String>> {
    let Some(value) = client.get(path, headers).await? else {
        return Ok(None);
    };
    let value = std::str::from_utf8(&value).with_context(|| format!("{path} is not valid UTF-8"))?;
    let value = value.trim();
    Ok((!value.is_empty()).then(|| value.to_owned()))
}

/// GETs raw user-data; an empty document counts as none (metadata services may answer 200 with
/// an empty body instead of 404).
async fn get_user_data(client: &http::Client, path: &str, headers: &[http::Header]) -> anyhow::Result<Option<Vec<u8>>> {
    let value = client.get(path, headers).await?;
    Ok(value.filter(|v| !v.is_empty()).map(Vec::from))
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
        std::fs::write(dir.path().join("product_name"), "Exoscale Compute Platform\n").unwrap();
        let dmi = Dmi::read(dir.path());
        assert_eq!(dmi.sys_vendor, "Exoscale");
        assert_eq!(Platform::from_dmi(&dmi), Some(Platform::Exoscale));
    }

    #[test]
    fn sanitizes_hostnames() {
        let cases = [
            ("node-1.example.com.", Some("node-1.example.com")),
            ("MyVM", Some("myvm")),
            ("worker-1.my_domain.local", Some("worker-1")),
            ("  web\n", Some("web")),
            ("", None),
            ("-bad.example.com_", None),
        ];
        for (raw, expected) in cases {
            assert_eq!(
                sanitize_hostname(raw).as_ref().map(Hostname::as_str),
                expected,
                "{raw:?}"
            );
        }
    }

    #[test]
    fn names_round_trip() {
        for platform in Platform::ALL {
            assert_eq!(Platform::from_name(platform.name()), Some(platform));
        }
    }
}

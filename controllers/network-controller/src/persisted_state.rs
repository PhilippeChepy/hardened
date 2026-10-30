//! What network-controller keeps across restarts: the DNS override, which machine-controller
//! configures once. Leases are not kept: a restart runs DHCP again.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Context as _;
use controllers_helpers::atomic_file;
use network_controller::DnsSettings;

/// Reads the override persisted in `path` (JSON); the default when it does not exist (nothing
/// configured yet).
pub fn load(path: &Path) -> anyhow::Result<DnsSettings> {
    let json = match fs::read_to_string(path) {
        Ok(json) => json,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(DnsSettings::default()),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))
}

/// Replaces `path` with `dns`. Its directory, the runtime directory, must exist.
pub fn save(path: &Path, dns: &DnsSettings) -> anyhow::Result<()> {
    let json = serde_json::to_string(dns).context("serializing the state")?;
    atomic_file::write(path, json.as_bytes(), 0o644)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(load(&path).unwrap(), DnsSettings::default());

        let dns = DnsSettings {
            name_servers: vec!["192.0.2.53".parse().unwrap()],
            search_list: vec!["corp.example".parse().unwrap()],
        };
        save(&path, &dns).unwrap();
        assert_eq!(load(&path).unwrap(), dns);

        fs::write(&path, r#"{"search-list": ["a b"]}"#).unwrap();
        assert!(load(&path).is_err(), "validated as user-data");
    }
}

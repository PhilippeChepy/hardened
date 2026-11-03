//! The interfaces' configurations, kept across restarts in [`Options::interfaces_file`]
//! (crate::options::Options): by interface name, as an interface keeps its name when it is
//! plugged in again.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use anyhow::Context as _;
use controllers_helpers::atomic_file;
use network_controller::InterfaceName;
use network_controller::InterfaceSettings;

/// The interfaces' configurations, by name: those configured through the API only.
pub type Configurations = BTreeMap<InterfaceName, InterfaceSettings>;

/// Reads the configurations persisted in `path` (JSON); none when it does not exist (nothing
/// configured yet).
pub fn load(path: &Path) -> anyhow::Result<Configurations> {
    let json = match fs::read_to_string(path) {
        Ok(json) => json,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Configurations::new()),
        Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
    };
    serde_json::from_str(&json).with_context(|| format!("parsing {}", path.display()))
}

/// Replaces `path` with `configurations`. Its directory must exist.
pub fn save(path: &Path, configurations: &Configurations) -> anyhow::Result<()> {
    let json = serde_json::to_string(configurations)
        .context("serializing the interfaces' configurations")?;
    atomic_file::write(path, json.as_bytes(), 0o644)
        .with_context(|| format!("writing {}", path.display()))
}

#[cfg(test)]
mod tests {
    use network_controller::Ipv4Method;
    use network_controller::StaticIpv4;

    use super::*;

    #[test]
    fn round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("interfaces.json");
        assert!(load(&path).unwrap().is_empty());

        let addresses = StaticIpv4::new(vec!["192.0.2.10/24".parse().unwrap()], None).unwrap();
        let settings = InterfaceSettings::new(
            true,
            Ipv4Method::Static(addresses),
            Default::default(),
            None,
        )
        .unwrap();
        let configurations = Configurations::from([("eth0".parse().unwrap(), settings)]);
        save(&path, &configurations).unwrap();
        assert_eq!(load(&path).unwrap(), configurations);
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            r#"{"eth0":{"enabled":true,"ipv4":{"static":{"addresses":["192.0.2.10/24"]}},"dns":{}}}"#
        );

        fs::write(&path, r#"{"eth/0": {}}"#).unwrap();
        assert!(load(&path).is_err(), "validated as the API's messages");
        fs::write(
            &path,
            r#"{"eth0": {"ipv4": {"static": {"addresses": []}}}}"#,
        )
        .unwrap();
        assert!(load(&path).is_err());
    }
}

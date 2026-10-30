//! What machine-controller keeps for the boot, so that a restart neither fetches the metadata
//! again nor reconfigures the controllers, which keep their own state.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Context;
use controllers_helpers::atomic_file;
use machine_controller::Settings;
use serde::Deserialize;
use serde::Serialize;

use crate::machine_identity::MachineIdentity;

/// Where the state is kept: a tmpfs, so a reboot starts over.
pub const PATH: &str = "/run/machine-controller/state.json";

/// The state, once the controllers are configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct State {
    pub identity: MachineIdentity,
    /// The settings of user-data (the defaults without valid user-data), secrets included.
    pub settings: Settings,
    /// Whether machine-apiproxy was enabled and configured, which happens after readiness: a
    /// restart retries until it was.
    pub api_proxy_configured: bool,
}

impl State {
    /// The state kept at `path`; `None` on the first start of the boot.
    ///
    /// # Errors
    ///
    /// When it cannot be read or parsed.
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let text = match fs::read(path) {
            Ok(text) => text,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| path.display().to_string()),
        };
        let state =
            serde_json::from_slice(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Some(state))
    }

    /// Keeps the state at `path`, readable by root only: the settings hold secrets.
    ///
    /// # Errors
    ///
    /// When it cannot be written.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(self).context("serializing the state")?;
        atomic_file::write(path, &json, 0o600).with_context(|| path.display().to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use machine_controller::UserData;

    use super::*;
    use crate::fake_controllers;
    use crate::metadata::Platform;

    fn identity() -> MachineIdentity {
        MachineIdentity {
            os_version: "1.0".to_owned(),
            kernel: "6.18.0".to_owned(),
            platform: Some(Platform::Qemu),
            instance_id: None,
            hostname: "node-1".parse().unwrap(),
            boot_id: Some("b00t".to_owned()),
            booted_at_unix_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(State::load(&path).unwrap(), None, "the first start");

        let settings = UserData::parse(fake_controllers::api_user_data().as_bytes())
            .unwrap()
            .settings;
        let state = State {
            identity: identity(),
            settings,
            api_proxy_configured: true,
        };
        state.save(&path).unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let loaded = State::load(&path).unwrap().unwrap();
        assert_eq!(loaded, state);
    }

    #[test]
    fn a_corrupt_state_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        fs::write(&path, "{").unwrap();
        assert!(State::load(&path).is_err());
        let settings = UserData::parse(b"[settings.network]\nhostname = \"web-1\"\n")
            .unwrap()
            .settings;
        let state = State {
            identity: identity(),
            settings,
            api_proxy_configured: false,
        };
        let state = serde_json::to_string(&state).unwrap();
        fs::write(&path, state.replace("\"web-1\"", "\"-web\"")).unwrap();
        assert!(State::load(&path).is_err(), "invalid settings");
    }
}

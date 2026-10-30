//! What time-controller keeps across restarts: its configuration, so that it polls again at once,
//! without machine-controller.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Context as _;
use controllers_helpers::atomic_file;
use serde::Deserialize;
use serde::Serialize;
use time_controller::TimeConfig;

/// The state file's contents (JSON).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PersistedState {
    /// The configuration last received.
    pub config: TimeConfig,
}

impl PersistedState {
    /// Reads `path`; `None` when it does not exist (never configured).
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let json = match fs::read_to_string(path) {
            Ok(json) => json,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err).with_context(|| format!("reading {}", path.display())),
        };
        serde_json::from_str(&json)
            .map(Some)
            .with_context(|| format!("parsing {}", path.display()))
    }

    /// Replaces `path` atomically. Its directory must exist: the sandbox does not allow `mkdir`,
    /// and serviced creates the runtime directory.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_string(self).context("serializing the state")?;
        atomic_file::write(path, json.as_bytes(), 0o644)
            .with_context(|| format!("writing {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use controllers_helpers::NonEmpty;
    use time_controller::TimeOrigin;

    use super::*;

    #[test]
    fn round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(PersistedState::load(&path).unwrap(), None);

        let state = PersistedState {
            config: TimeConfig {
                servers: NonEmpty::new("time.example.com".parse().unwrap()),
                origin: TimeOrigin::Dhcp,
            },
        };
        state.save(&path).unwrap();
        assert_eq!(PersistedState::load(&path).unwrap(), Some(state));
        let entries: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(entries, ["state.json"], "no temporary file left");

        fs::write(
            &path,
            r#"{"config": {"servers": ["ntp://x"], "origin": "dhcp"}}"#,
        )
        .unwrap();
        assert!(PersistedState::load(&path).is_err(), "validated");
        fs::write(&path, r#"{"config": {"servers": [], "origin": "dhcp"}}"#).unwrap();
        assert!(PersistedState::load(&path).is_err(), "no server");
    }
}

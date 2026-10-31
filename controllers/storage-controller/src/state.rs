//! What storage-controller did, kept in its runtime directory so that a restart carries on
//! without being configured again.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Context as _;
use serde::Deserialize;
use serde::Serialize;
use storage_controller::Encryption;

use crate::backing::Backing;

/// Where the state is kept: in `/run`, so every boot starts afresh.
pub const PATH: &str = "/run/storage-controller/state.json";

/// How far `/var` is set up on this boot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "kebab-case")]
pub enum State {
    /// Configured, but `/var` is not set up yet, or no longer since `stop`.
    Configured {
        /// The first configuration's: later ones take effect at the next boot.
        encryption: Encryption,
    },
    /// `/var` is set up.
    SetUp {
        /// What backs it, and so the encryption it was configured with.
        backing: Backing,
    },
}

impl State {
    /// The state at `path`; `None` when there is none.
    pub fn load(path: &Path) -> anyhow::Result<Option<Self>> {
        let json = match fs::read(path) {
            Ok(json) => json,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        serde_json::from_slice(&json)
            .map(Some)
            .with_context(|| format!("parsing {}", path.display()))
    }

    /// Writes the state at `path`, atomically: a restart finds this one or the previous one.
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let json = serde_json::to_vec(self).context("encoding the state")?;
        let partial = path.with_extension("json.partial");
        fs::write(&partial, json)
            .and_then(|()| fs::rename(&partial, path))
            .with_context(|| format!("writing {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(State::load(&path).unwrap(), None);

        let configured = State::Configured {
            encryption: Encryption::Tpm,
        };
        configured.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), Some(configured));

        let set_up = State::SetUp {
            backing: Backing::Formatted {
                partition: "/dev/vda4".into(),
                reason: "it was not encrypted (first boot with encryption)".into(),
            },
        };
        set_up.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), Some(set_up));
        assert_eq!(
            fs::read_dir(dir.path()).unwrap().count(),
            1,
            "no partial file left"
        );

        fs::write(&path, "{").unwrap();
        assert!(State::load(&path).is_err());
    }
}

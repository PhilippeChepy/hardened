//! What kubelet-controller applied, kept in [`PATH`] so a restarted kubelet-controller applies it
//! again without being configured.

use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::Path;

use controllers_helpers::atomic_file;
use serde::Deserialize;
use serde::Serialize;

use crate::rendered::Rendered;

/// Where the state is kept.
pub const PATH: &str = "/run/kubelet-controller/state.json";

/// The last configuration applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct State {
    /// kubelet's files and arguments; `None` when it does not run.
    pub kubelet: Option<Rendered>,
}

impl State {
    /// The state kept in `path`; `None` before the first configuration.
    ///
    /// # Errors
    ///
    /// When the file cannot be read or parsed.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Keeps the state in `path`, replaced atomically, readable by root only (credentials).
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        atomic_file::write(path, &serde_json::to_vec_pretty(self)?, 0o600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendered;
    use crate::rendered::tests::config;

    #[test]
    fn round_trips_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(State::load(&path).unwrap(), None);
        let state = State {
            kubelet: Some(rendered::render(&config(""), &"node-1".parse().unwrap())),
        };
        state.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), Some(state));
        let disabled = State { kubelet: None };
        disabled.save(&path).unwrap();
        assert_eq!(State::load(&path).unwrap(), Some(disabled));
    }
}

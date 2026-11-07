//! Where firewall-controller keeps its configuration, and where a system gives its default.

use std::path::Path;
use std::path::PathBuf;

/// The directory keeping the configuration across reboots, when the service file binds it: a
/// system whose `/var` is mounted before firewall-controller starts. Otherwise the configuration
/// is kept across restarts only, in [`RUNTIME_DIR`], and the system's configuration manager sets
/// it again at every boot.
pub const PERSISTENT_DIR: &str = "/var/lib/firewall-controller";
/// The runtime directory.
pub const RUNTIME_DIR: &str = "/run/firewall-controller";
/// The system's default configuration (a [`PersistedState`](crate::persisted_state::PersistedState)
/// document), when it ships one: applied when none is kept, and by `ResetConfig`. Without it, the
/// built-in default applies: on, nothing let in.
pub const DEFAULT_FILE: &str = "/usr/lib/firewall-controller/default.json";

/// Where [`run`](crate::run::run) reads and keeps its files; the default is the production one.
#[derive(Debug)]
pub struct Options {
    /// The configuration kept: in [`PERSISTENT_DIR`] when the sandbox has it, in [`RUNTIME_DIR`]
    /// otherwise.
    pub state_file: PathBuf,
    /// The system's default configuration, if any.
    pub default_file: PathBuf,
}

impl Default for Options {
    fn default() -> Self {
        let persistent = Path::new(PERSISTENT_DIR);
        let dir = if persistent.is_dir() {
            persistent
        } else {
            Path::new(RUNTIME_DIR)
        };
        Self {
            state_file: dir.join("config.json"),
            default_file: DEFAULT_FILE.into(),
        }
    }
}

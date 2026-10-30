//! Where services and their logs are.

use std::path::{Path, PathBuf};

use crate::definition::ServiceName;

/// The image's services, shipped by the components they run.
pub(crate) const IMAGE_DIR: &str = "/usr/lib/serviced/services";
/// This boot's services, written by services.
pub const RUNTIME_DIR: &str = "/run/serviced/services";
/// Services kept across boots, on the state partition.
pub(crate) const PERSISTENT_DIR: &str = "/var/lib/serviced/services";
/// Logs of the services started before `/var` is mounted.
pub const RUN_LOG_DIR: &str = "/run/serviced/logs";
/// Logs of the services started once `/var` is mounted.
pub const VAR_LOG_DIR: &str = "/var/log/serviced";

/// Where service logs go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogDir {
    /// [`VAR_LOG_DIR`].
    Var,
    /// [`RUN_LOG_DIR`].
    Run,
}

/// Where service `name`'s output goes in `dir`.
#[must_use]
pub fn log_path(name: &ServiceName, dir: LogDir) -> PathBuf {
    let dir = match dir {
        LogDir::Var => VAR_LOG_DIR,
        LogDir::Run => RUN_LOG_DIR,
    };
    Path::new(dir).join(format!("{name}.log"))
}

//! The configuration machine-apiproxy keeps for the boot, so that a restart serves at once.

use std::fs;
use std::io;
use std::path::Path;

use anyhow::Context;
use controllers_helpers::atomic_file;
use machine_apiproxy::ApiConfig;

/// Where the configuration is kept, in machine-apiproxy's runtime directory.
pub const PATH: &str = "/run/machine-apiproxy/state.json";

/// Keeps `config` at `path`, readable by machine-apiproxy only: it holds the private key.
///
/// # Errors
///
/// When it cannot be written.
pub fn save(path: &Path, config: &ApiConfig) -> anyhow::Result<()> {
    let json = serde_json::to_vec(config).context("serializing the configuration")?;
    atomic_file::write(path, &json, 0o600).with_context(|| path.display().to_string())
}

/// The configuration kept at `path`, validated as user-data's; `None` before the first one.
///
/// # Errors
///
/// When it cannot be read, or is invalid.
pub fn load(path: &Path) -> anyhow::Result<Option<ApiConfig>> {
    let json = match fs::read(path) {
        Ok(json) => json,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| path.display().to_string()),
    };
    let config = serde_json::from_slice(&json)
        .with_context(|| format!("invalid configuration in {}", path.display()))?;
    Ok(Some(config))
}

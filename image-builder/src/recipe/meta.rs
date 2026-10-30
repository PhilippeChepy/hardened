//! What the SBOM says about a component.

use serde::{Deserialize, Serialize};

use crate::recipe::ComponentName;

/// The OS version: image-builder's, which the serviced and controllers workspaces share.
pub const WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// CycloneDX 1.6 component type (the subset hardened's components use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentType {
    Application,
    Library,
    OperatingSystem,
    Firmware,
}

/// What the SBOM says about a component.
#[derive(Debug, Clone)]
pub struct Meta {
    /// The component's name.
    pub name: ComponentName,
    /// Its upstream version (or [`WORKSPACE_VERSION`]).
    pub version: String,
    /// Its CycloneDX type.
    pub kind: ComponentType,
    /// One line about it.
    pub summary: String,
    /// SPDX license expression.
    pub license: String,
    /// Its upstream's site.
    pub homepage: String,
    /// Package URL; `pkg:generic/<name>@<version>` unless the recipe sets one.
    pub purl: String,
    /// Its CPE, for vulnerability databases, if it has one.
    pub cpe: Option<String>,
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    #[test]
    fn the_workspaces_share_the_os_version() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for workspace in ["serviced", "controllers"] {
            let manifest =
                std::fs::read_to_string(root.join(workspace).join("Cargo.toml")).unwrap();
            let manifest: toml::Table = manifest.parse().unwrap();
            assert_eq!(
                manifest["workspace"]["package"]["version"].as_str(),
                Some(WORKSPACE_VERSION),
                "{workspace}"
            );
        }
    }
}

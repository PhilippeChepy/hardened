//! An image-based workload, as user-data and the API declare it.

use std::collections::BTreeMap;

use controllers_helpers::Argument;
use controllers_helpers::validated_string;
use serde::{Deserialize, Serialize};

use crate::{ContainerPath, ImageRef, VarPath};

/// What to run for an image-based workload, wherever it was declared (user-data or the API).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ImageWorkload {
    /// The image to run.
    pub image: ImageRef,
    /// The program and its arguments, replacing the image's entrypoint and command; empty, the
    /// image's. Whole: `ctr run` cannot keep the image's entrypoint while replacing its command.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<Argument>,
    /// Environment variables, added to the image's.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<EnvName, EnvValue>,
    /// Runs with all capabilities and host devices, no seccomp filter and unmasked `/proc` and
    /// `/sys`.
    #[serde(default)]
    pub privileged: bool,
    /// When serviced restarts the workload.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// Host directories bound into the container.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountSettings>,
    /// Also copies the workload's output to the serial console (debugging, smoke tests).
    #[serde(default)]
    pub console: bool,
}

validated_string!(
    /// An environment variable's value, which `execve` takes: without NUL bytes.
    EnvValue,
    "environment variable value",
    check_no_nul
);

fn check_no_nul(text: &str) -> Result<(), &'static str> {
    if text.contains('\0') {
        Err("must not contain NUL bytes")
    } else {
        Ok(())
    }
}

validated_string!(
    /// Environment variable name: non-empty, without `=` or NUL.
    EnvName,
    "environment variable name",
    check_env_name
);

fn check_env_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.contains(['=', '\0']) {
        Err("must be non-empty, without '=' or NUL")
    } else {
        Ok(())
    }
}

/// When serviced restarts a workload's service.
#[allow(missing_docs, reason = "self-explanatory variants")]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    Always,
    OnFailure,
    Never,
}

/// A host directory bound into a workload's container.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MountSettings {
    /// The host directory, below `/var`; created if missing.
    pub source: VarPath,
    /// Where the container sees it.
    pub destination: ContainerPath,
    /// Binds it read-only.
    #[serde(default)]
    pub read_only: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execve_strings_reject_nul_bytes() {
        let workload: ImageWorkload =
            toml::from_str("image = \"nginx\"\ncommand = [\"nginx\", \"-t\"]\n").unwrap();
        let text = toml::to_string(&workload).unwrap();
        assert_eq!(toml::from_str::<ImageWorkload>(&text).unwrap(), workload);
        for bad in [
            "image = \"nginx\"\ncommand = [\"a\\u0000b\"]\n",
            "image = \"nginx\"\nenv = { A = \"a\\u0000b\" }\n",
        ] {
            assert!(toml::from_str::<ImageWorkload>(bad).is_err(), "{bad}");
        }
    }
}

//! What a workload may do on the host.

use serde::{Deserialize, Serialize};

use crate::ContainerPath;

/// A workload's privileges. User-data writes them `privileged = false`, `privileged = true` or,
/// with what only a privileged workload may add, as a table (`privileged.host-root = "/host"`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "PrivilegedSetting", into = "PrivilegedSetting")]
pub enum Privileges {
    /// runc's defaults: its capabilities and seccomp profile, `no_new_privs`, masked `/proc`.
    #[default]
    Unprivileged,
    /// Every capability and host device, no seccomp filter, unmasked `/proc` and `/sys`.
    Privileged {
        /// Where the host's `/` is mounted, recursively read-only.
        host_root: Option<ContainerPath>,
    },
}

impl Privileges {
    /// Whether the workload runs privileged.
    #[must_use]
    pub fn is_privileged(&self) -> bool {
        matches!(self, Self::Privileged { .. })
    }
}

/// The value of `privileged` in user-data.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum PrivilegedSetting {
    Flag(bool),
    Table(PrivilegedTable),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct PrivilegedTable {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    host_root: Option<ContainerPath>,
}

impl From<PrivilegedSetting> for Privileges {
    fn from(setting: PrivilegedSetting) -> Self {
        match setting {
            PrivilegedSetting::Flag(false) => Self::Unprivileged,
            PrivilegedSetting::Flag(true) => Self::Privileged { host_root: None },
            PrivilegedSetting::Table(table) => Self::Privileged {
                host_root: table.host_root,
            },
        }
    }
}

impl From<Privileges> for PrivilegedSetting {
    fn from(privileges: Privileges) -> Self {
        match privileges {
            Privileges::Unprivileged => Self::Flag(false),
            Privileges::Privileged { host_root: None } => Self::Flag(true),
            Privileges::Privileged { host_root } => Self::Table(PrivilegedTable { host_root }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct Spec {
        privileged: Privileges,
    }

    #[test]
    fn reads_a_flag_or_a_table() {
        for (text, privileges) in [
            ("privileged = false\n", Privileges::Unprivileged),
            (
                "privileged = true\n",
                Privileges::Privileged { host_root: None },
            ),
            (
                "[privileged]\nhost-root = \"/host\"\n",
                Privileges::Privileged {
                    host_root: Some("/host".parse().unwrap()),
                },
            ),
        ] {
            let spec: Spec = toml::from_str(text).unwrap();
            assert_eq!(spec.privileged, privileges, "{text}");
            assert_eq!(toml::to_string(&spec).unwrap(), text);
        }
        for bad in [
            "privileged.host-root = \"host\"\n",
            "privileged.host = \"/host\"\n",
            "privileged = 1\n",
        ] {
            assert!(toml::from_str::<Spec>(bad).is_err(), "{bad}");
        }
    }
}

//! What backs `/var` on this boot.

use std::path::PathBuf;

use serde::Deserialize;
use serde::Serialize;
use storage_controller::Encryption;
use storage_controller::storage;

/// What backs `/var` on this boot, which implies the encryption it was set up with. An encrypted
/// partition is mounted from [`crate::encryption::MAPPED`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Backing {
    /// The state partition, unencrypted.
    Plain {
        /// The partition's device, mounted on `/var`.
        partition: PathBuf,
    },
    /// The encrypted state partition, opened with the key trust-controller unsealed.
    Unlocked {
        /// The partition's device.
        partition: PathBuf,
    },
    /// The encrypted state partition, formatted on this boot (what it held is gone).
    Formatted {
        /// The partition's device.
        partition: PathBuf,
        /// Why it was formatted.
        reason: String,
    },
    /// A tmpfs: nothing persists.
    Tmpfs {
        /// The encryption the state partition was to be set up with.
        encryption: Encryption,
        /// Why the state partition is not used.
        reason: String,
    },
}

impl Backing {
    /// The encryption `/var` was set up with.
    #[must_use]
    pub fn encryption(&self) -> Encryption {
        match self {
            Self::Plain { .. } => Encryption::None,
            Self::Unlocked { .. } | Self::Formatted { .. } => Encryption::Tpm,
            Self::Tmpfs { encryption, .. } => *encryption,
        }
    }
}

impl From<Backing> for storage::state::Backing {
    fn from(backing: Backing) -> Self {
        let path = |path: PathBuf| path.to_string_lossy().into_owned();
        match backing {
            Backing::Plain { partition } => Self::Plain(storage::state::Plain {
                partition: path(partition),
            }),
            Backing::Unlocked { partition } => Self::Unlocked(storage::state::Unlocked {
                partition: path(partition),
            }),
            Backing::Formatted { partition, reason } => {
                Self::Formatted(storage::state::Formatted {
                    partition: path(partition),
                    reason,
                })
            }
            Backing::Tmpfs { reason, .. } => Self::Tmpfs(storage::state::Tmpfs { reason }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn converts_to_the_proto() {
        assert_eq!(
            storage::state::Backing::from(Backing::Formatted {
                partition: "/dev/vda4".into(),
                reason: "it held no known format".into(),
            }),
            storage::state::Backing::Formatted(storage::state::Formatted {
                partition: "/dev/vda4".into(),
                reason: "it held no known format".into(),
            })
        );
    }
}

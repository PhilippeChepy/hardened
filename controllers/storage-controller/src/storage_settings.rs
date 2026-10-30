//! `[settings.hardened.storage]`.

use serde::{Deserialize, Serialize};

/// `[settings.hardened.storage]`: the state partition, mounted on `/var`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct StorageSettings {
    /// How the state partition is encrypted.
    #[serde(default)]
    pub encryption: Encryption,
}

/// How the state partition is encrypted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Encryption {
    /// A plain ext4 filesystem.
    #[default]
    None,
    /// LUKS2, with a random key sealed to the TPM's PCR 11: only this machine, booting this image,
    /// opens it.
    Tpm,
}

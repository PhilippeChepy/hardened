//! `settings.hardened.storage` as storage-controller's configuration.

use controllers_helpers::InvalidMessage;

use crate::storage;
use crate::{Encryption, StorageSettings};

impl From<StorageSettings> for storage::Configuration {
    fn from(settings: StorageSettings) -> Self {
        let encryption = match settings.encryption {
            Encryption::None => storage::Encryption::None,
            Encryption::Tpm => storage::Encryption::Tpm,
        };
        Self {
            encryption: encryption.into(),
        }
    }
}

/// An unspecified encryption is rejected rather than defaulted: storage-controller formats the
/// state partition according to it.
impl TryFrom<storage::Configuration> for StorageSettings {
    type Error = InvalidMessage;

    fn try_from(message: storage::Configuration) -> Result<Self, Self::Error> {
        let encryption = match storage::Encryption::try_from(message.encryption) {
            Ok(storage::Encryption::None) => Encryption::None,
            Ok(storage::Encryption::Tpm) => Encryption::Tpm,
            Ok(storage::Encryption::Unspecified) | Err(_) => {
                return Err(InvalidMessage::new("encryption", "must be set"));
            }
        };
        Ok(Self { encryption })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for encryption in [Encryption::None, Encryption::Tpm] {
            let settings = StorageSettings { encryption };
            let message = storage::Configuration::from(settings.clone());
            assert_eq!(StorageSettings::try_from(message).unwrap(), settings);
        }
    }

    #[test]
    fn rejects_an_unspecified_encryption() {
        for encryption in [storage::Encryption::Unspecified.into(), 7] {
            let error = StorageSettings::try_from(storage::Configuration { encryption });
            assert_eq!(error.unwrap_err().field(), "encryption");
        }
    }
}

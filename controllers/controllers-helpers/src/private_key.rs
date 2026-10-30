//! PEM private keys.

use std::fmt;

use rustls_pki_types::PrivateKeyDer;
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};

use crate::InvalidValue;
use crate::base64_text;

/// A PEM private key, checked to decode. Base64-encoded in settings, and serialized back as such
/// (machine-controller keeps the settings). Never displayed or logged: its `Debug` implementation
/// prints `<redacted>`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PrivateKey(String);

impl PrivateKey {
    /// What secrets show in place of their value.
    pub const REDACTED: &str = "<redacted>";
    const KIND: &str = "private key PEM";

    /// Checks that `pem` holds a private key that decodes.
    pub fn from_pem(pem: String) -> Result<Self, InvalidValue> {
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| InvalidValue::new(Self::KIND, "<pem>", "cannot be decoded"))?;
        Ok(Self(pem))
    }

    /// The PEM text, to hand to the TLS server. The only way to read the key.
    #[must_use]
    pub fn expose_pem(&self) -> &str {
        &self.0
    }
}

/// From the base64 of the PEM text.
impl TryFrom<String> for PrivateKey {
    type Error = InvalidValue;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        Self::from_pem(base64_text::pem_from_base64(Self::KIND, &encoded)?)
    }
}

/// To the base64 of the PEM text.
impl From<PrivateKey> for String {
    fn from(key: PrivateKey) -> Self {
        base64_text::encode(key.0)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn private_keys_are_never_shown_but_serialize_back() {
        let (_, key) = testing::certificate_and_key();
        let encoded = base64_text::encode(&key);
        assert!(PrivateKey::try_from(key).is_err(), "raw PEM is not base64");
        let key = PrivateKey::try_from(encoded.clone()).unwrap();
        assert_eq!(format!("{key:?}"), "<redacted>");
        assert_eq!(
            serde_json::to_string(&key).unwrap(),
            format!("\"{encoded}\"")
        );
        assert!(PrivateKey::try_from(base64_text::encode(PrivateKey::REDACTED)).is_err());
    }
}

//! PEM certificates.

use std::fmt;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use serde::{Deserialize, Serialize};

use crate::InvalidValue;
use crate::base64_text;

/// One or more PEM certificates (a chain or a CA bundle), checked to decode. Base64-encoded in
/// settings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Certificates(String);

impl Certificates {
    const KIND: &str = "certificate PEM";

    /// Checks that `pem` holds at least one certificate, and that each one decodes.
    pub fn from_pem(pem: String) -> Result<Self, InvalidValue> {
        let reject = |reason| InvalidValue::new(Self::KIND, "<pem>", reason);
        let mut count: usize = 0;
        for certificate in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            certificate.map_err(|_| reject("cannot be decoded"))?;
            count += 1;
        }
        if count == 0 {
            return Err(reject("contains no certificate"));
        }
        Ok(Self(pem))
    }

    /// The PEM text.
    #[must_use]
    pub fn pem(&self) -> &str {
        &self.0
    }
}

/// From the base64 of the PEM text.
impl TryFrom<String> for Certificates {
    type Error = InvalidValue;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        Self::from_pem(base64_text::pem_from_base64(Self::KIND, &encoded)?)
    }
}

/// To the base64 of the PEM text.
impl From<Certificates> for String {
    fn from(value: Certificates) -> Self {
        base64_text::encode(value.0)
    }
}

impl fmt::Debug for Certificates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Certificates(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing;

    #[test]
    fn certificates() {
        let (cert, key) = testing::certificate_and_key();
        let encoded = base64_text::encode(&cert);
        let certs = Certificates::try_from(encoded.clone()).unwrap();
        assert_eq!(certs.pem(), cert);
        assert_eq!(String::from(certs), encoded, "serializes back to base64");
        // `base64` wraps its output at 76 columns.
        let wrapped: String = encoded
            .as_bytes()
            .chunks(76)
            .map(|line| format!("{}\n", std::str::from_utf8(line).unwrap()))
            .collect();
        assert!(Certificates::try_from(wrapped).is_ok());
        assert!(
            Certificates::try_from(cert).is_err(),
            "raw PEM is not base64"
        );
        assert!(Certificates::try_from(base64_text::encode("garbage")).is_err());
        assert!(
            Certificates::try_from(base64_text::encode(key)).is_err(),
            "a key is not a certificate"
        );
    }
}

//! trust-controller's encoding of a sealed secret (`SealedSecret.sealed`).
//!
//! A JSON object with the fields of systemd's `systemd-tpm2` LUKS2 token, with their meanings:
//! storage-controller stores them in the LUKS2 header as its `hardened-tpm2` token, so they are
//! an on-disk format, readable with `cryptsetup luksDump`.

use anyhow::Context as _;
use anyhow::ensure;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::Deserialize;
use serde::Serialize;

use crate::marshal::Reader;
use crate::marshal::Writer;
use crate::tpm_error::TpmError;

/// systemd-stub measures the UKI (kernel, command line with the verity root hash, os-release)
/// into PCR 11: a secret sealed to it unseals only when booting this very image.
pub const PCRS: [u32; 1] = [11];

/// A secret sealed by [`Tpm::seal`](crate::tpm::Tpm::seal): the TPM2B_PRIVATE and TPM2B_PUBLIC
/// contents of a data object of the storage key. Not secret: only the TPM that sealed it unseals
/// it, and only in the PCR state it was sealed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The TPM2B_PRIVATE contents: the secret, encrypted by the storage key.
    pub private: Vec<u8>,
    /// The TPM2B_PUBLIC contents: the object's TPMT_PUBLIC, with its policy.
    pub public: Vec<u8>,
}

impl Sealed {
    /// The marshalled TPM2B_PRIVATE then TPM2B_PUBLIC (the layout of systemd's `tpm2-blob`).
    #[must_use]
    fn to_blob(&self) -> Vec<u8> {
        let mut w = Writer::default();
        w.tpm2b(&self.private).tpm2b(&self.public);
        w.into_bytes()
    }

    /// Parses what [`Sealed::to_blob`] writes.
    fn from_blob(blob: &[u8]) -> Result<Self, TpmError> {
        let mut r = Reader::new(blob);
        let private = r.tpm2b()?.to_vec();
        let public = r.tpm2b()?.to_vec();
        r.finish()?;
        Ok(Self { private, public })
    }
}

/// The bank of [`PCRS`]: the only one sealed to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PcrBank {
    Sha256,
}

/// The storage key the object is created under: the owner hierarchy's ECC P-256 primary key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PrimaryAlg {
    Ecc,
}

/// A secret sealed to [`PCRS`], and the PolicyPCR digest of the values it was sealed to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub struct SealedObject {
    /// base64 of the marshalled TPM2B_PRIVATE and TPM2B_PUBLIC (systemd's `tpm2-blob`).
    tpm2_blob: String,
    tpm2_pcrs: Vec<u32>,
    tpm2_pcr_bank: PcrBank,
    tpm2_primary_alg: PrimaryAlg,
    /// hex.
    tpm2_policy_hash: String,
}

impl SealedObject {
    /// `sealed` under `policy`.
    #[must_use]
    pub fn new(sealed: &Sealed, policy: &[u8; 32]) -> Self {
        use base64::Engine as _;

        Self {
            tpm2_blob: BASE64.encode(sealed.to_blob()),
            tpm2_pcrs: PCRS.to_vec(),
            tpm2_pcr_bank: PcrBank::Sha256,
            tpm2_primary_alg: PrimaryAlg::Ecc,
            tpm2_policy_hash: hex::encode(policy),
        }
    }

    /// The bytes of `SealedSecret.sealed`.
    ///
    /// # Errors
    ///
    /// When JSON fails to serialize it.
    pub fn encode(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    /// The sealed object and its policy, from what [`SealedObject::encode`] wrote. Fails on
    /// anything this trust-controller would not have sealed.
    pub fn decode(bytes: &[u8]) -> anyhow::Result<(Sealed, [u8; 32])> {
        use base64::Engine as _;

        let object: Self = serde_json::from_slice(bytes).context("not a sealed object")?;
        ensure!(
            object.tpm2_pcrs == PCRS,
            "sealed to PCRs {:?}, not {PCRS:?}",
            object.tpm2_pcrs
        );
        let blob = BASE64.decode(&object.tpm2_blob).context("tpm2-blob")?;
        let sealed = Sealed::from_blob(&blob).context("tpm2-blob")?;
        let mut policy = [0; 32];
        hex::decode_to_slice(&object.tpm2_policy_hash, &mut policy).context("tpm2-policy-hash")?;
        Ok((sealed, policy))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed() -> Sealed {
        Sealed {
            private: vec![1, 2, 3],
            public: vec![4, 5],
        }
    }

    const POLICY: [u8; 32] = [0xaa; 32];

    #[test]
    fn round_trips() {
        let encoded = SealedObject::new(&sealed(), &POLICY).encode().unwrap();
        assert_eq!(SealedObject::decode(&encoded).unwrap(), (sealed(), POLICY));
    }

    /// The on-disk format: the fields of the `hardened-tpm2` token.
    #[test]
    fn decodes_the_token_fields() {
        let token = br#"{"tpm2-blob":"AAMBAgMAAgQF","tpm2-pcrs":[11],"tpm2-pcr-bank":"sha256",
            "tpm2-primary-alg":"ecc",
            "tpm2-policy-hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;
        assert_eq!(SealedObject::decode(token).unwrap(), (sealed(), POLICY));
    }

    #[test]
    fn encodes_the_token_fields() {
        let encoded = SealedObject::new(&sealed(), &POLICY).encode().unwrap();
        let expected = concat!(
            r#"{"tpm2-blob":"AAMBAgMAAgQF","tpm2-pcrs":[11],"tpm2-pcr-bank":"sha256","#,
            r#""tpm2-primary-alg":"ecc","#,
            r#""tpm2-policy-hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#,
        );
        assert_eq!(String::from_utf8(encoded).unwrap(), expected);
    }

    #[test]
    fn rejects_what_it_did_not_seal() {
        let object = serde_json::to_value(SealedObject::new(&sealed(), &POLICY)).unwrap();
        for (field, value) in [
            ("tpm2-pcrs", serde_json::json!([7, 11])),
            ("tpm2-pcr-bank", "sha1".into()),
            ("tpm2-primary-alg", "rsa".into()),
            ("tpm2-blob", "AAMBAg==".into()),         // truncated
            ("tpm2-blob", "AAMBAgMAAgQFAA==".into()), // a trailing byte
            ("tpm2-policy-hash", "aa".into()),
        ] {
            let mut broken = object.clone();
            broken[field] = value;
            let broken = serde_json::to_vec(&broken).unwrap();
            assert!(SealedObject::decode(&broken).is_err(), "{field}");
        }
        assert!(SealedObject::decode(b"not json").is_err());
    }
}

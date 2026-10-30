//! Verifying a quote (`Attestation/Quote`) where the machine is not trusted: its signature by
//! the attestation key, a restricted key the TPM only signs its own attestations with, the nonce,
//! and that the PCR values are those the TPM quoted.

use std::collections::BTreeMap;

use ring::signature::ECDSA_P256_SHA256_FIXED;
use ring::signature::UnparsedPublicKey;
use sha2::Digest as _;
use sha2::Sha256;

use crate::attestation::HashAlgorithm;
use crate::attestation::QuoteResponse;

const TPM_GENERATED: u32 = 0xff54_4347;
const ST_ATTEST_QUOTE: u16 = 0x8018;
const RH_ENDORSEMENT: u32 = 0x4000_000b;
const ALG_SHA1: u16 = 0x0004;
const ALG_SHA256: u16 = 0x000b;
const ALG_SHA384: u16 = 0x000c;
const ALG_ECDSA: u16 = 0x0018;
const ALG_NULL: u16 = 0x0010;
const ALG_ECC: u16 = 0x0023;
const ECC_NIST_P256: u16 = 0x0003;
const RESTRICTED: u32 = 1 << 16;
const SIGN: u32 = 1 << 18;
const FIXED_TPM: u32 = 1 << 1;

/// Why a quote is not valid.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// A structure could not be parsed.
    #[error("malformed {0}")]
    Malformed(&'static str),
    /// The attestation key is not a restricted ECDSA P-256 signing key bound to the TPM.
    #[error("the attestation key is not a restricted ECDSA P-256 signing key of the TPM")]
    NotAnAttestationKey,
    /// The signature does not verify with the attestation key.
    #[error("the signature does not verify with the attestation key")]
    BadSignature,
    /// The TPM did not produce the signed structure, or it is not a quote.
    #[error("the signed structure is not a TPM-generated quote")]
    NotAQuote,
    /// The quote is signed by another key than the attestation key returned.
    #[error("the quote's signer is not the attestation key")]
    WrongSigner,
    /// The quote is not over the nonce: it may be replayed.
    #[error("the quote is not over the nonce")]
    WrongNonce,
    /// The quote covers other PCRs, or another bank, than the values returned.
    #[error("the quote covers other PCRs than the values returned")]
    WrongSelection,
    /// The PCR values returned are not those quoted.
    #[error("the PCR values returned are not those quoted")]
    WrongPcrValues,
}

/// What a valid quote proves: the attestation key's TPM had these PCR values in `bank`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedQuote {
    /// The bank of the values.
    pub bank: HashAlgorithm,
    /// The PCR values, by index.
    pub pcrs: BTreeMap<u32, Vec<u8>>,
}

/// Verifies `quote`, requested over `nonce` in `bank`. Whether its attestation key is the
/// expected one is the caller's to check (`quote.ak_public`).
///
/// # Errors
///
/// When any check fails.
pub fn verify(
    quote: &QuoteResponse,
    nonce: &[u8],
    bank: HashAlgorithm,
) -> Result<VerifiedQuote, VerificationError> {
    let key = attestation_key(&quote.ak_public)?;
    let signature = signature(&quote.signature)?;
    UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, key)
        .verify(&quote.attest, &signature)
        .map_err(|_| VerificationError::BadSignature)?;

    let mut r = Reader::new(&quote.attest, "quote");
    if r.u32()? != TPM_GENERATED || r.u16()? != ST_ATTEST_QUOTE {
        return Err(VerificationError::NotAQuote);
    }
    if r.tpm2b()? != qualified_name(&quote.ak_public) {
        return Err(VerificationError::WrongSigner);
    }
    if r.tpm2b()? != nonce {
        return Err(VerificationError::WrongNonce);
    }
    // clockInfo (clock, resetCount, restartCount, safe), firmwareVersion.
    r.take(8 + 4 + 4 + 1 + 8)?;
    let (hash, select) = match r.u32()? {
        1 => (r.u16()?, r.u8_sized()?),
        _ => return Err(VerificationError::WrongSelection),
    };
    let pcr_digest = r.tpm2b()?;
    r.finish()?;

    let quoted: Vec<u32> = (0..u32::try_from(select.len() * 8).unwrap_or(0))
        .filter(|&pcr| select[(pcr / 8) as usize] & (1 << (pcr % 8)) != 0)
        .collect();
    let returned: Vec<u32> = quote.values.iter().map(|value| value.index).collect();
    if hash != algorithm_id(bank) || quoted != returned {
        return Err(VerificationError::WrongSelection);
    }
    let mut hasher = Sha256::new();
    for value in &quote.values {
        hasher.update(&value.digest);
    }
    if hasher.finalize().as_slice() != pcr_digest {
        return Err(VerificationError::WrongPcrValues);
    }
    Ok(VerifiedQuote {
        bank,
        pcrs: quote
            .values
            .iter()
            .map(|value| (value.index, value.digest.clone()))
            .collect(),
    })
}

#[must_use]
fn algorithm_id(bank: HashAlgorithm) -> u16 {
    match bank {
        HashAlgorithm::Sha1 => ALG_SHA1,
        HashAlgorithm::Sha256 | HashAlgorithm::Unspecified => ALG_SHA256,
        HashAlgorithm::Sha384 => ALG_SHA384,
    }
}

/// The uncompressed P-256 point of the attestation key's TPMT_PUBLIC, checking it is the
/// restricted signing key trust-controller creates.
fn attestation_key(public: &[u8]) -> Result<Vec<u8>, VerificationError> {
    let mut r = Reader::new(public, "attestation key");
    let (kind, name_alg, attributes) = (r.u16()?, r.u16()?, r.u32()?);
    r.tpm2b()?; // authPolicy
    let parameters = [r.u16()?, r.u16()?, r.u16()?, r.u16()?, r.u16()?];
    let (x, y) = (r.tpm2b()?, r.tpm2b()?);
    r.finish()?;
    let required = RESTRICTED | SIGN | FIXED_TPM;
    if kind != ALG_ECC
        || name_alg != ALG_SHA256
        || attributes & required != required
        || parameters != [ALG_NULL, ALG_ECDSA, ALG_SHA256, ECC_NIST_P256, ALG_NULL]
    {
        return Err(VerificationError::NotAnAttestationKey);
    }
    Ok([&[0x04][..], &scalar(x)?, &scalar(y)?].concat())
}

/// The attestation key's qualified name: a primary key of the endorsement hierarchy.
#[must_use]
fn qualified_name(public: &[u8]) -> Vec<u8> {
    let name_alg = ALG_SHA256.to_be_bytes();
    let name = [&name_alg[..], &Sha256::digest(public)].concat();
    let qualified = Sha256::new()
        .chain_update(RH_ENDORSEMENT.to_be_bytes())
        .chain_update(name)
        .finalize();
    [&name_alg[..], &qualified].concat()
}

/// The `r || s` of an ECDSA-SHA256 TPMT_SIGNATURE.
fn signature(signature: &[u8]) -> Result<Vec<u8>, VerificationError> {
    let mut r = Reader::new(signature, "signature");
    if r.u16()? != ALG_ECDSA || r.u16()? != ALG_SHA256 {
        return Err(VerificationError::Malformed("signature: not ECDSA-SHA256"));
    }
    let (sig_r, sig_s) = (r.tpm2b()?, r.tpm2b()?);
    r.finish()?;
    Ok([scalar(sig_r)?, scalar(sig_s)?].concat())
}

/// A P-256 scalar or coordinate as 32 bytes: TPMs may strip its leading zeros.
fn scalar(bytes: &[u8]) -> Result<[u8; 32], VerificationError> {
    let mut padded = [0; 32];
    let start = 32_usize
        .checked_sub(bytes.len())
        .ok_or(VerificationError::Malformed(
            "P-256 value longer than 32 bytes",
        ))?;
    padded[start..].copy_from_slice(bytes);
    Ok(padded)
}

/// Bounds-checked cursor over a marshalled structure.
struct Reader<'bytes> {
    bytes: &'bytes [u8],
    what: &'static str,
}

impl<'bytes> Reader<'bytes> {
    fn new(bytes: &'bytes [u8], what: &'static str) -> Self {
        Self { bytes, what }
    }

    fn take(&mut self, n: usize) -> Result<&'bytes [u8], VerificationError> {
        let (head, tail) = self
            .bytes
            .split_at_checked(n)
            .ok_or(VerificationError::Malformed(self.what))?;
        self.bytes = tail;
        Ok(head)
    }

    fn u8(&mut self) -> Result<u8, VerificationError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, VerificationError> {
        let bytes = self.take(2)?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    fn u32(&mut self) -> Result<u32, VerificationError> {
        Ok((u32::from(self.u16()?) << 16) | u32::from(self.u16()?))
    }

    fn tpm2b(&mut self) -> Result<&'bytes [u8], VerificationError> {
        let len = self.u16()?;
        self.take(len.into())
    }

    fn u8_sized(&mut self) -> Result<&'bytes [u8], VerificationError> {
        let len = self.u8()?;
        self.take(len.into())
    }

    fn finish(self) -> Result<(), VerificationError> {
        if self.bytes.is_empty() {
            Ok(())
        } else {
            Err(VerificationError::Malformed(self.what))
        }
    }
}

#[cfg(test)]
mod tests {
    use ring::rand::SystemRandom;
    use ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING;
    use ring::signature::EcdsaKeyPair;
    use ring::signature::KeyPair as _;

    use super::*;
    use crate::attestation::PcrValue;

    const NONCE: &[u8] = b"verifier nonce";

    fn tpm2b(bytes: &[u8]) -> Vec<u8> {
        let len = u16::try_from(bytes.len()).unwrap().to_be_bytes();
        [&len[..], bytes].concat()
    }

    /// A software TPM: an attestation key and the quotes it signs.
    struct Tpm {
        key: EcdsaKeyPair,
        public: Vec<u8>,
    }

    impl Tpm {
        fn new(attributes: u32) -> Self {
            let random = SystemRandom::new();
            let pkcs8 =
                EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &random).unwrap();
            let key =
                EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &random)
                    .unwrap();
            let point = key.public_key().as_ref();
            let mut public = Vec::new();
            for field in [ALG_ECC, ALG_SHA256] {
                public.extend(field.to_be_bytes());
            }
            public.extend(attributes.to_be_bytes());
            public.extend(tpm2b(&[]));
            for field in [ALG_NULL, ALG_ECDSA, ALG_SHA256, ECC_NIST_P256, ALG_NULL] {
                public.extend(field.to_be_bytes());
            }
            public.extend(tpm2b(&point[1..33]));
            public.extend(tpm2b(&point[33..]));
            Self { key, public }
        }

        /// A quote of `values` (SHA-256 bank) over `nonce`, `pcr_digest` overriding theirs.
        fn quote(&self, nonce: &[u8], values: &[(u32, [u8; 32])]) -> QuoteResponse {
            let mut select = [0_u8; 3];
            let mut digest = Sha256::new();
            for (index, value) in values {
                select[*index as usize / 8] |= 1 << (index % 8);
                digest.update(value);
            }
            let mut attest = Vec::new();
            attest.extend(TPM_GENERATED.to_be_bytes());
            attest.extend(ST_ATTEST_QUOTE.to_be_bytes());
            attest.extend(tpm2b(&qualified_name(&self.public)));
            attest.extend(tpm2b(nonce));
            attest.extend([0; 25]);
            attest.extend(1_u32.to_be_bytes());
            attest.extend(ALG_SHA256.to_be_bytes());
            attest.push(3);
            attest.extend(select);
            attest.extend(tpm2b(&digest.finalize()));
            let mut quote = QuoteResponse {
                attest,
                ak_public: self.public.clone(),
                values: values
                    .iter()
                    .map(|(index, digest)| PcrValue {
                        index: *index,
                        digest: digest.to_vec(),
                    })
                    .collect(),
                ..QuoteResponse::default()
            };
            self.sign(&mut quote);
            quote
        }

        /// Signs `quote.attest` again.
        fn sign(&self, quote: &mut QuoteResponse) {
            let random = SystemRandom::new();
            let fixed = self.key.sign(&random, &quote.attest).unwrap();
            let (r, s) = fixed.as_ref().split_at(32);
            let mut signature = Vec::new();
            signature.extend(ALG_ECDSA.to_be_bytes());
            signature.extend(ALG_SHA256.to_be_bytes());
            signature.extend(tpm2b(r));
            signature.extend(tpm2b(s));
            quote.signature = signature;
        }
    }

    const AK: u32 = RESTRICTED | SIGN | FIXED_TPM;
    const PCRS: [(u32, [u8; 32]); 2] = [(7, [7; 32]), (11, [11; 32])];

    #[test]
    fn verifies_a_quote() {
        let tpm = Tpm::new(AK);
        let verified = verify(&tpm.quote(NONCE, &PCRS), NONCE, HashAlgorithm::Sha256).unwrap();
        assert_eq!(verified.pcrs[&11], [11; 32]);
        assert_eq!(verified.pcrs.len(), 2);
    }

    #[test]
    fn rejects_what_does_not_hold() {
        let tpm = Tpm::new(AK);
        let check =
            |quote: &QuoteResponse| verify(quote, NONCE, HashAlgorithm::Sha256).unwrap_err();

        let replayed = tpm.quote(b"another nonce", &PCRS);
        assert!(matches!(check(&replayed), VerificationError::WrongNonce));

        let mut lying = tpm.quote(NONCE, &PCRS);
        lying.values[1].digest = vec![0; 32];
        assert!(matches!(check(&lying), VerificationError::WrongPcrValues));

        let mut fewer = tpm.quote(NONCE, &PCRS);
        fewer.values.pop();
        assert!(matches!(check(&fewer), VerificationError::WrongSelection));

        let mut forged = tpm.quote(NONCE, &PCRS);
        forged.attest[30] ^= 1;
        assert!(matches!(check(&forged), VerificationError::BadSignature));

        let mut other_key = tpm.quote(NONCE, &PCRS);
        other_key.ak_public = Tpm::new(AK).public;
        assert!(matches!(check(&other_key), VerificationError::BadSignature));

        let unrestricted = Tpm::new(SIGN | FIXED_TPM);
        let quote = unrestricted.quote(NONCE, &PCRS);
        assert!(matches!(
            check(&quote),
            VerificationError::NotAnAttestationKey
        ));

        let mut not_a_quote = tpm.quote(NONCE, &PCRS);
        not_a_quote.attest[4..6].copy_from_slice(&0x8014_u16.to_be_bytes());
        tpm.sign(&mut not_a_quote);
        assert!(matches!(check(&not_a_quote), VerificationError::NotAQuote));
    }
}

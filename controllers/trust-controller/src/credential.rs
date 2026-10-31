//! Credentials for credential activation (TPM2_MakeCredential, TPM 2.0 Part 1, §24), made by a
//! verifier for an attestation key and an endorsement key (EK): only the TPM holding both can
//! activate it and return its secret, so a verifier trusting the EK (its certificate, or a pinned
//! key) learns that the attestation key is that TPM's.
//!
//! The EKs are those of the TCG's EK Credential Profile low-range templates: RSA 2048 (L-1) and
//! ECC NIST P-256 (L-2), decryption keys protecting with AES-128-CFB, authorized by
//! PolicySecret(TPM_RH_ENDORSEMENT).

use aes::Aes128;
use cfb_mode::cipher::KeyIvInit as _;
use num_bigint::BigUint;
use ring::agreement;
use ring::hmac;
use ring::rand::{SecureRandom as _, SystemRandom};
use sha2::Digest as _;
use sha2::Sha256;

const ALG_RSA: u16 = 0x0001;
const ALG_AES: u16 = 0x0006;
const ALG_SHA256: u16 = 0x000b;
const ALG_NULL: u16 = 0x0010;
const ALG_ECC: u16 = 0x0023;
const ALG_CFB: u16 = 0x0043;
const ECC_NIST_P256: u16 = 0x0003;
/// fixedTPM, fixedParent, sensitiveDataOrigin, adminWithPolicy, restricted, decrypt.
const EK_ATTRIBUTES: u32 = 0x0003_00b2;
/// PolicySecret(TPM_RH_ENDORSEMENT): the EK templates' authPolicy.
const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];
const RSA_EXPONENT: u32 = 65537;

/// Why a credential cannot be made.
#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    /// The EK's TPMT_PUBLIC is not one of the EK templates.
    #[error("the endorsement key is not an RSA 2048 or ECC P-256 EK: {0}")]
    NotAnEndorsementKey(&'static str),
    /// The attestation key's TPMT_PUBLIC is malformed.
    #[error("malformed attestation key")]
    MalformedAttestationKey,
    /// The credential does not fit a TPM2B_DIGEST.
    #[error("the credential is longer than 32 bytes")]
    CredentialTooLong,
    /// The system's random source, or the key agreement, failed.
    #[error("cryptography failed: {0}")]
    Crypto(&'static str),
}

/// An endorsement key's public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EndorsementKey {
    /// RSA 2048, exponent 65537: its modulus, big-endian.
    Rsa {
        /// The modulus.
        modulus: Vec<u8>,
    },
    /// ECC NIST P-256: its point.
    Ecc {
        /// The point's x coordinate, 32 bytes.
        x: [u8; 32],
        /// The point's y coordinate, 32 bytes.
        y: [u8; 32],
    },
}

impl EndorsementKey {
    /// The key of the EK whose TPMT_PUBLIC is `public`, checking it is one of the templates'.
    ///
    /// # Errors
    ///
    /// When it is not.
    pub fn from_public(public: &[u8]) -> Result<Self, CredentialError> {
        let not = CredentialError::NotAnEndorsementKey;
        let mut r = Reader(public);
        let kind = r.u16().ok_or(not("truncated"))?;
        let name_alg = r.u16().ok_or(not("truncated"))?;
        let attributes = r.u32().ok_or(not("truncated"))?;
        let policy = r.tpm2b().ok_or(not("truncated"))?;
        if name_alg != ALG_SHA256 || attributes != EK_ATTRIBUTES || policy != EK_POLICY {
            return Err(not(
                "not the template's name algorithm, attributes or policy",
            ));
        }
        let symmetric = [r.u16(), r.u16(), r.u16()];
        if symmetric != [Some(ALG_AES), Some(128), Some(ALG_CFB)] || r.u16() != Some(ALG_NULL) {
            return Err(not("not protecting with AES-128-CFB"));
        }
        let key = match kind {
            ALG_RSA => {
                if r.u16() != Some(2048) || r.u32() != Some(0) {
                    return Err(not("not RSA 2048 with the default exponent"));
                }
                let modulus = r.tpm2b().ok_or(not("truncated"))?;
                if modulus.len() != 256 {
                    return Err(not("a modulus of other than 256 bytes"));
                }
                Self::Rsa {
                    modulus: modulus.to_vec(),
                }
            }
            ALG_ECC => {
                if r.u16() != Some(ECC_NIST_P256) || r.u16() != Some(ALG_NULL) {
                    return Err(not("not on NIST P-256"));
                }
                let (x, y) = (r.tpm2b(), r.tpm2b());
                let coordinate = |c: Option<&[u8]>| -> Result<[u8; 32], CredentialError> {
                    c.and_then(|c| c.try_into().ok())
                        .ok_or(not("a coordinate of other than 32 bytes"))
                };
                Self::Ecc {
                    x: coordinate(x)?,
                    y: coordinate(y)?,
                }
            }
            _ => return Err(not("neither RSA nor ECC")),
        };
        if !r.0.is_empty() {
            return Err(not("trailing bytes"));
        }
        Ok(key)
    }
}

/// A credential for TPM2_ActivateCredential, both its parameters' contents.
#[derive(Debug, Clone)]
pub struct Credential {
    /// The TPM2B_ID_OBJECT contents: the integrity HMAC, then the encrypted credential.
    pub blob: Vec<u8>,
    /// The TPM2B_ENCRYPTED_SECRET contents: the seed, encrypted to the EK.
    pub secret: Vec<u8>,
}

/// The credential protecting `credential` (at most 32 bytes) for the attestation key whose
/// TPMT_PUBLIC is `ak_public`, under the endorsement key `ek`.
///
/// # Errors
///
/// When the credential is too long, the attestation key malformed, or cryptography fails.
pub fn make(
    ek: &EndorsementKey,
    ak_public: &[u8],
    credential: &[u8],
) -> Result<Credential, CredentialError> {
    if credential.len() > 32 {
        return Err(CredentialError::CredentialTooLong);
    }
    let ak_name = name(ak_public)?;
    let random = SystemRandom::new();
    let (seed, secret) = match ek {
        EndorsementKey::Rsa { modulus } => {
            let mut seed = [0; 32];
            random
                .fill(&mut seed)
                .map_err(|_| CredentialError::Crypto("random"))?;
            (seed, rsa_oaep(modulus, b"IDENTITY\0", &seed, &random)?)
        }
        EndorsementKey::Ecc { x, y } => {
            let ephemeral =
                agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &random)
                    .map_err(|_| CredentialError::Crypto("ECDH key generation"))?;
            let public = ephemeral
                .compute_public_key()
                .map_err(|_| CredentialError::Crypto("ECDH public key"))?;
            let point = [&[0x04][..], x, y].concat();
            let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, point);
            let ephemeral_x = &public.as_ref()[1..33];
            let seed = agreement::agree_ephemeral(ephemeral, &peer, |z| {
                kdfe(z, b"IDENTITY\0", ephemeral_x, x)
            })
            .map_err(|_| CredentialError::Crypto("ECDH with the endorsement key"))?;
            let secret = [tpm2b(ephemeral_x)?, tpm2b(&public.as_ref()[33..])?].concat();
            (seed, secret)
        }
    };

    let symmetric: [u8; 16] = kdfa(&seed, b"STORAGE", &ak_name, &[]);
    let mut encrypted = tpm2b(credential)?;
    cfb_mode::Encryptor::<Aes128>::new(&symmetric.into(), &[0; 16].into()).encrypt(&mut encrypted);
    let integrity: [u8; 32] = kdfa(&seed, b"INTEGRITY", &[], &[]);
    let key = hmac::Key::new(hmac::HMAC_SHA256, &integrity);
    let hmac = hmac::sign(&key, &[&encrypted[..], &ak_name].concat());
    Ok(Credential {
        blob: [tpm2b(hmac.as_ref())?, encrypted].concat(),
        secret,
    })
}

/// An object's name: its name algorithm (SHA-256) and the digest of its TPMT_PUBLIC.
fn name(public: &[u8]) -> Result<Vec<u8>, CredentialError> {
    if public.get(2..4) != Some(&ALG_SHA256.to_be_bytes()[..]) {
        return Err(CredentialError::MalformedAttestationKey);
    }
    Ok([&ALG_SHA256.to_be_bytes()[..], &Sha256::digest(public)].concat())
}

fn tpm2b(bytes: &[u8]) -> Result<Vec<u8>, CredentialError> {
    let len =
        u16::try_from(bytes.len()).map_err(|_| CredentialError::Crypto("a TPM2B over 64 KiB"))?;
    Ok([&len.to_be_bytes()[..], bytes].concat())
}

/// KDFa with SHA-256 (TPM 2.0 Part 1, §11.4.10.2): HMAC in counter mode, `N` bytes.
fn kdfa<const N: usize>(key: &[u8], label: &[u8], context_u: &[u8], context_v: &[u8]) -> [u8; N] {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    let bits = u32::try_from(N * 8).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(N + 32);
    let mut counter = 1_u32;
    while out.len() < N {
        let mut context = hmac::Context::with_key(&key);
        context.update(&counter.to_be_bytes());
        context.update(label);
        context.update(&[0]);
        context.update(context_u);
        context.update(context_v);
        context.update(&bits.to_be_bytes());
        out.extend_from_slice(context.sign().as_ref());
        counter += 1;
    }
    std::array::from_fn(|i| out[i])
}

/// KDFe with SHA-256 for a 256-bit seed (TPM 2.0 Part 1, §11.4.10.3), `label` with its NUL.
fn kdfe(z: &[u8], label: &[u8], party_u: &[u8], party_v: &[u8]) -> [u8; 32] {
    Sha256::new()
        .chain_update(1_u32.to_be_bytes())
        .chain_update(z)
        .chain_update(label)
        .chain_update(party_u)
        .chain_update(party_v)
        .finalize()
        .into()
}

/// MGF1 with SHA-256 (RFC 8017, B.2.1).
fn mgf1(seed: &[u8], len: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(len + 32);
    let mut counter = 0_u32;
    while mask.len() < len {
        mask.extend_from_slice(
            &Sha256::new()
                .chain_update(seed)
                .chain_update(counter.to_be_bytes())
                .finalize(),
        );
        counter += 1;
    }
    mask.truncate(len);
    mask
}

/// RSAES-OAEP encryption with SHA-256 and MGF1-SHA-256 (RFC 8017, §7.1.1) of `message` under
/// the public key of `modulus` and exponent 65537. Public data only: no constant-time need.
fn rsa_oaep(
    modulus: &[u8],
    label: &[u8],
    message: &[u8],
    random: &SystemRandom,
) -> Result<Vec<u8>, CredentialError> {
    let k = modulus.len();
    let mut db = Vec::with_capacity(k - 33);
    db.extend_from_slice(&Sha256::digest(label));
    db.resize(k - 2 * 32 - 2 - message.len() + 32, 0);
    db.push(1);
    db.extend_from_slice(message);
    let mut seed = [0; 32];
    random
        .fill(&mut seed)
        .map_err(|_| CredentialError::Crypto("random"))?;
    for (byte, mask) in db.iter_mut().zip(mgf1(&seed, k - 33)) {
        *byte ^= mask;
    }
    for (byte, mask) in seed.iter_mut().zip(mgf1(&db, 32)) {
        *byte ^= mask;
    }
    let encoded = BigUint::from_bytes_be(&[&[0][..], &seed, &db].concat());
    let n = BigUint::from_bytes_be(modulus);
    let encrypted = encoded
        .modpow(&BigUint::from(RSA_EXPONENT), &n)
        .to_bytes_be();
    let mut out = vec![0; k - encrypted.len()];
    out.extend_from_slice(&encrypted);
    Ok(out)
}

/// A cursor over a marshalled structure.
struct Reader<'bytes>(&'bytes [u8]);

impl<'bytes> Reader<'bytes> {
    fn take(&mut self, n: usize) -> Option<&'bytes [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_be_bytes(self.take(2)?.try_into().ok()?))
    }

    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_be_bytes(self.take(4)?.try_into().ok()?))
    }

    fn tpm2b(&mut self) -> Option<&'bytes [u8]> {
        let len = self.u16()?;
        self.take(len.into())
    }
}

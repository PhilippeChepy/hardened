//! The TPM 2.0 commands trust-controller issues (TPM 2.0 Part 3), as pure encode/decode
//! functions.

use sha2::{Digest, Sha256};

use crate::marshal;
use crate::marshal::Auth;
use crate::marshal::Reader;
use crate::marshal::Writer;
use crate::sealed_object::Sealed;
use crate::tpm_error::TpmError;

const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const CC_CREATE: u32 = 0x0000_0153;
const CC_LOAD: u32 = 0x0000_0157;
const CC_QUOTE: u32 = 0x0000_0158;
const CC_UNSEAL: u32 = 0x0000_015e;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const CC_PCR_READ: u32 = 0x0000_017e;
const CC_POLICY_PCR: u32 = 0x0000_017f;
const CC_ACTIVATE_CREDENTIAL: u32 = 0x0000_0147;
const CC_NV_READ: u32 = 0x0000_014e;
const CC_POLICY_SECRET: u32 = 0x0000_0151;
const CC_NV_READ_PUBLIC: u32 = 0x0000_0169;

/// TPM_RH_OWNER: the owner (storage) hierarchy.
pub const RH_OWNER: u32 = 0x4000_0001;
const RH_NULL: u32 = 0x4000_0007;
/// TPM_RH_ENDORSEMENT: the endorsement hierarchy.
pub const RH_ENDORSEMENT: u32 = 0x4000_000b;

/// TPM_ALG_ID of the hash algorithms.
pub const ALG_SHA1: u16 = 0x0004;
const ALG_RSA: u16 = 0x0001;
pub const ALG_SHA256: u16 = 0x000b;
pub const ALG_SHA384: u16 = 0x000c;
const ALG_AES: u16 = 0x0006;
const ALG_KEYEDHASH: u16 = 0x0008;
const ALG_ECDSA: u16 = 0x0018;
const ALG_NULL: u16 = 0x0010;
const ALG_ECC: u16 = 0x0023;
const ALG_CFB: u16 = 0x0043;
const ECC_NIST_P256: u16 = 0x0003;

/// TPMA_OBJECT bits.
const FIXED_TPM: u32 = 1 << 1;
const FIXED_PARENT: u32 = 1 << 4;
const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
const USER_WITH_AUTH: u32 = 1 << 6;
const NO_DA: u32 = 1 << 10;
const ADMIN_WITH_POLICY: u32 = 1 << 7;
const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;
const SIGN: u32 = 1 << 18;

/// TPM_SE_POLICY.
const SE_POLICY: u8 = 0x01;

/// TPM_GENERATED_VALUE: "\xffTCG", proves a TPMS_ATTEST was produced by the TPM.
const TPM_GENERATED: u32 = 0xff54_4347;
const ST_ATTEST_QUOTE: u16 = 0x8018;

/// One TPMS_PCR_SELECTION: a bank and a bitmap of its PCRs (bit `i` is PCR `i`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcrSelection {
    /// The bank's TPM_ALG_ID.
    pub hash: u16,
    /// Bit `i` selects PCR `i`.
    pub mask: u32,
}

impl PcrSelection {
    /// PC Client TPMs have 24 PCRs, selected with 3 bytes.
    const SIZE_OF_SELECT: u8 = 3;

    /// The selected PCRs, by ascending index.
    pub fn indices(self) -> impl Iterator<Item = u32> {
        (0..u32::BITS).filter(move |i| self.mask & (1 << i) != 0)
    }

    fn encode(self, w: &mut Writer) {
        debug_assert!(self.mask < 1 << 24, "PCR selection beyond PCR 23");
        let select = self.mask.to_le_bytes();
        w.u16(self.hash)
            .u8(Self::SIZE_OF_SELECT)
            .bytes(&select[..Self::SIZE_OF_SELECT.into()]);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, TpmError> {
        let hash = r.u16()?;
        let select = r.u8_sized()?;
        if select.len() > 4 {
            return Err(TpmError::Malformed("PCR selection beyond PCR 31"));
        }
        let mask = select
            .iter()
            .rev()
            .fold(0, |mask, &b| mask << 8 | u32::from(b));
        Ok(Self { hash, mask })
    }
}

/// Marshals a TPML_PCR_SELECTION.
fn encode_selections(w: &mut Writer, selections: &[PcrSelection]) {
    w.u32(u32::try_from(selections.len()).expect("too many PCR selections"));
    for selection in selections {
        selection.encode(w);
    }
}

fn decode_selections(r: &mut Reader<'_>) -> Result<Vec<PcrSelection>, TpmError> {
    (0..r.u32()?).map(|_| PcrSelection::decode(r)).collect()
}

/// TPM2_PCR_Read.
#[must_use]
pub fn pcr_read(selection: PcrSelection) -> Vec<u8> {
    marshal::command(CC_PCR_READ, &[], Auth::None, |w| {
        encode_selections(w, &[selection])
    })
}

/// The output parameters of TPM2_PCR_Read.
#[derive(Debug)]
pub struct PcrReadOut<'response> {
    /// Incremented by every PCR extension: two reads with the same counter are consistent.
    pub update_counter: u32,
    /// What the TPM actually read: possibly a subset of the request.
    pub selections: Vec<PcrSelection>,
    /// One digest per selected PCR, in selection order.
    pub digests: Vec<&'response [u8]>,
}

/// The output of TPM2_PCR_Read.
pub fn parse_pcr_read(response: &[u8]) -> Result<PcrReadOut<'_>, TpmError> {
    let mut r = marshal::response(response, 0)?.params;
    let update_counter = r.u32()?;
    let selections = decode_selections(&mut r)?;
    let digests = (0..r.u32()?).map(|_| r.tpm2b()).collect::<Result<_, _>>()?;
    r.finish()?;
    Ok(PcrReadOut {
        update_counter,
        selections,
        digests,
    })
}

/// TPMT_PUBLIC of the attestation key: a restricted ECDSA-P256-SHA256 signing key with empty
/// auth, bound to this TPM.
#[must_use]
pub fn ak_template() -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(ALG_ECC)
        .u16(ALG_SHA256)
        .u32(FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | RESTRICTED | SIGN)
        .tpm2b(&[]) // authPolicy
        // TPMS_ECC_PARMS: symmetric, scheme + hashAlg, curveID, kdf.
        .u16(ALG_NULL)
        .u16(ALG_ECDSA)
        .u16(ALG_SHA256)
        .u16(ECC_NIST_P256)
        .u16(ALG_NULL)
        // unique: empty TPMS_ECC_POINT.
        .tpm2b(&[])
        .tpm2b(&[]);
    w.into_bytes()
}

/// PolicySecret(TPM_RH_ENDORSEMENT): the authPolicy of the EK templates.
const EK_POLICY: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];

/// The endorsement keys of the TCG EK Credential Profile's low-range templates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EkType {
    /// RSA 2048 (template L-1), its certificate at NV index 0x01c00002.
    Rsa2048,
    /// ECC NIST P-256 (template L-2), its certificate at NV index 0x01c0000a.
    EccP256,
}

impl EkType {
    /// The NV index of the EK certificate of this type.
    #[must_use]
    pub fn certificate_index(self) -> u32 {
        match self {
            Self::Rsa2048 => 0x01c0_0002,
            Self::EccP256 => 0x01c0_000a,
        }
    }

    /// TPMT_PUBLIC of the EK: a restricted decryption key with AES-128-CFB, authorized by
    /// PolicySecret(TPM_RH_ENDORSEMENT), the same on every TPM given its endorsement seed.
    #[must_use]
    pub fn template(self) -> Vec<u8> {
        let mut w = Writer::default();
        w.u16(match self {
            Self::Rsa2048 => ALG_RSA,
            Self::EccP256 => ALG_ECC,
        })
        .u16(ALG_SHA256)
        .u32(
            FIXED_TPM
                | FIXED_PARENT
                | SENSITIVE_DATA_ORIGIN
                | ADMIN_WITH_POLICY
                | RESTRICTED
                | DECRYPT,
        )
        .tpm2b(&EK_POLICY)
        // symmetric (algorithm, keyBits, mode), scheme.
        .u16(ALG_AES)
        .u16(128)
        .u16(ALG_CFB)
        .u16(ALG_NULL);
        match self {
            // keyBits, exponent (the default), unique: a zeroed modulus.
            Self::Rsa2048 => w.u16(2048).u32(0).tpm2b(&[0; 256]),
            // curveID, kdf, unique: a zeroed point.
            Self::EccP256 => w
                .u16(ECC_NIST_P256)
                .u16(ALG_NULL)
                .tpm2b(&[0; 32])
                .tpm2b(&[0; 32]),
        };
        w.into_bytes()
    }
}

/// TPM2_NV_ReadPublic of `index`.
#[must_use]
pub fn nv_read_public(index: u32) -> Vec<u8> {
    marshal::command(CC_NV_READ_PUBLIC, &[index], Auth::None, |_| {})
}

/// The size of the NV index TPM2_NV_ReadPublic described.
pub fn parse_nv_read_public(response: &[u8]) -> Result<u16, TpmError> {
    let mut params = marshal::response(response, 0)?.params;
    let mut public = Reader::new(params.tpm2b()?);
    // TPMS_NV_PUBLIC: nvIndex, nameAlg, attributes, authPolicy, dataSize.
    public.take(4 + 2 + 4)?;
    public.tpm2b()?;
    public.u16()
}

/// TPM2_NV_Read of `size` bytes of `index` from `offset`, authorized by the index itself (with
/// an empty password).
#[must_use]
pub fn nv_read(index: u32, size: u16, offset: u16) -> Vec<u8> {
    marshal::command(CC_NV_READ, &[index, index], Auth::EmptyPassword, |w| {
        w.u16(size).u16(offset);
    })
}

/// The data TPM2_NV_Read read.
pub fn parse_nv_read(response: &[u8]) -> Result<Vec<u8>, TpmError> {
    let mut params = marshal::response(response, 0)?.params;
    Ok(params.tpm2b()?.to_vec())
}

/// TPM2_PolicySecret of the endorsement hierarchy (its empty password), in the policy
/// `session`: what the EK's policy requires.
#[must_use]
pub fn policy_secret_endorsement(session: u32) -> Vec<u8> {
    marshal::command(
        CC_POLICY_SECRET,
        &[RH_ENDORSEMENT, session],
        Auth::EmptyPassword,
        |w| {
            // nonceTPM, cpHashA, policyRef: empty; expiration: none.
            w.tpm2b(&[]).tpm2b(&[]).tpm2b(&[]).u32(0);
        },
    )
}

/// TPM2_ActivateCredential of `blob` and `secret` for the attestation key `key` (its empty
/// password) and the EK `ek`, authorized by the policy `session`.
#[must_use]
pub fn activate_credential(
    key: u32,
    ek: u32,
    session: u32,
    nonce: &[u8],
    blob: &[u8],
    secret: &[u8],
) -> Vec<u8> {
    marshal::command(
        CC_ACTIVATE_CREDENTIAL,
        &[key, ek],
        Auth::PasswordThenPolicy { session, nonce },
        |w| {
            w.tpm2b(blob).tpm2b(secret);
        },
    )
}

/// The credential TPM2_ActivateCredential recovered.
pub fn parse_activate_credential(response: &[u8]) -> Result<Vec<u8>, TpmError> {
    let mut params = marshal::response(response, 0)?.params;
    Ok(params.tpm2b()?.to_vec())
}

/// TPMT_PUBLIC of the storage key sealed objects are created under: the TCG's ECC P-256 storage
/// root key template (restricted decryption key, AES-128-CFB for its children), with empty auth
/// and no dictionary-attack protection.
#[must_use]
pub fn srk_template() -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(ALG_ECC)
        .u16(ALG_SHA256)
        .u32(
            FIXED_TPM
                | FIXED_PARENT
                | SENSITIVE_DATA_ORIGIN
                | USER_WITH_AUTH
                | NO_DA
                | RESTRICTED
                | DECRYPT,
        )
        .tpm2b(&[]) // authPolicy
        // TPMS_ECC_PARMS: symmetric (algorithm, keyBits, mode), scheme, curveID, kdf.
        .u16(ALG_AES)
        .u16(128)
        .u16(ALG_CFB)
        .u16(ALG_NULL)
        .u16(ECC_NIST_P256)
        .u16(ALG_NULL)
        // unique: empty TPMS_ECC_POINT.
        .tpm2b(&[])
        .tpm2b(&[]);
    w.into_bytes()
}

/// TPMT_PUBLIC of a sealed data object that only a policy session satisfying `policy` (a SHA-256
/// policy digest) can unseal: `userWithAuth` is clear, so its (empty) auth value cannot.
#[must_use]
pub fn sealed_template(policy: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(ALG_KEYEDHASH)
        .u16(ALG_SHA256)
        .u32(FIXED_TPM | FIXED_PARENT | NO_DA)
        .tpm2b(policy)
        // TPMS_KEYEDHASH_PARMS: no scheme (a data object).
        .u16(ALG_NULL)
        // unique: empty TPM2B_DIGEST.
        .tpm2b(&[]);
    w.into_bytes()
}

/// TPM2_CreatePrimary under `hierarchy` (authorized with an empty password).
#[must_use]
pub fn create_primary(hierarchy: u32, template: &[u8]) -> Vec<u8> {
    create_command(CC_CREATE_PRIMARY, hierarchy, &[], template)
}

/// TPM2_CreatePrimary and TPM2_Create share their parameters.
fn create_command(code: u32, parent: u32, data: &[u8], template: &[u8]) -> Vec<u8> {
    marshal::command(code, &[parent], Auth::EmptyPassword, |w| {
        w.sized(|w| {
            // TPMS_SENSITIVE_CREATE: userAuth, data.
            w.tpm2b(&[]).tpm2b(data);
        })
        .tpm2b(template)
        .tpm2b(&[]); // outsideInfo
        encode_selections(w, &[]); // creationPCR
    })
}

/// A primary key TPM2_CreatePrimary created.
#[derive(Debug, PartialEq, Eq)]
pub struct Primary {
    /// Its transient handle.
    pub handle: u32,
    /// Its TPMT_PUBLIC (the TPM2B_PUBLIC contents).
    pub public: Vec<u8>,
}

/// The key TPM2_CreatePrimary created.
pub fn parse_create_primary(response: &[u8]) -> Result<Primary, TpmError> {
    let marshal::Response {
        mut handles,
        mut params,
    } = marshal::response(response, 1)?;
    let handle = handles.u32()?;
    let public = params.tpm2b()?;
    // creationData, creationHash, creationTicket and name follow; nothing here needs them.
    Ok(Primary {
        handle,
        public: public.to_vec(),
    })
}

/// TPM2_Create of a data object holding `data` under `parent` (authorized with an empty
/// password).
#[must_use]
pub fn create(parent: u32, data: &[u8], template: &[u8]) -> Vec<u8> {
    create_command(CC_CREATE, parent, data, template)
}

/// The TPM2B_PRIVATE and TPM2B_PUBLIC contents of the created object.
pub fn parse_create(response: &[u8]) -> Result<Sealed, TpmError> {
    let mut params = marshal::response(response, 0)?.params;
    let private = params.tpm2b()?;
    let public = params.tpm2b()?;
    // creationData, creationHash and creationTicket follow; nothing here needs them.
    Ok(Sealed {
        private: private.to_vec(),
        public: public.to_vec(),
    })
}

/// TPM2_Load of an object created under `parent` (authorized with an empty password).
#[must_use]
pub fn load(parent: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
    marshal::command(CC_LOAD, &[parent], Auth::EmptyPassword, |w| {
        w.tpm2b(private).tpm2b(public);
    })
}

/// The handle a command returns: TPM2_Load's object, TPM2_StartAuthSession's session.
pub fn parse_handle(response: &[u8]) -> Result<u32, TpmError> {
    marshal::response(response, 1)?.handles.u32()
}

/// TPM2_StartAuthSession of an unbound, unsalted policy session hashing with SHA-256.
#[must_use]
pub fn start_policy_session(nonce: &[u8]) -> Vec<u8> {
    marshal::command(
        CC_START_AUTH_SESSION,
        &[RH_NULL, RH_NULL],
        Auth::None,
        |w| {
            w.tpm2b(nonce)
                .tpm2b(&[]) // encryptedSalt
                .u8(SE_POLICY)
                .u16(ALG_NULL) // symmetric: no parameter encryption
                .u16(ALG_SHA256);
        },
    )
}

/// TPM2_PolicyPCR over `selection` at their current values (an empty `pcrDigest`).
#[must_use]
pub fn policy_pcr(session: u32, selection: PcrSelection) -> Vec<u8> {
    marshal::command(CC_POLICY_PCR, &[session], Auth::None, |w| {
        w.tpm2b(&[]);
        encode_selections(w, &[selection]);
    })
}

/// The policy digest TPM2_PolicyPCR leaves in a fresh SHA-256 session for `selection` at
/// values whose concatenation hashes to `pcr_digest` (TPM 2.0 Part 3, §23.7).
#[must_use]
pub fn policy_pcr_digest(selection: PcrSelection, pcr_digest: &[u8]) -> [u8; 32] {
    let mut selections = Writer::default();
    encode_selections(&mut selections, &[selection]);
    Sha256::new()
        .chain_update([0; 32])
        .chain_update(CC_POLICY_PCR.to_be_bytes())
        .chain_update(selections.into_bytes())
        .chain_update(pcr_digest)
        .finalize()
        .into()
}

/// TPM2_Unseal of `object`, authorized by the policy `session`.
#[must_use]
pub fn unseal(object: u32, session: u32, nonce: &[u8]) -> Vec<u8> {
    marshal::command(
        CC_UNSEAL,
        &[object],
        Auth::Policy { session, nonce },
        |_| {},
    )
}

/// The unsealed data.
pub fn parse_unseal(response: &[u8]) -> Result<Vec<u8>, TpmError> {
    let mut params = marshal::response(response, 0)?.params;
    let data = params.tpm2b()?.to_vec();
    params.finish()?;
    Ok(data)
}

/// TPM2_Quote with `key` (authorized with an empty password) and its own signing scheme.
#[must_use]
pub fn quote(key: u32, nonce: &[u8], selection: PcrSelection) -> Vec<u8> {
    marshal::command(CC_QUOTE, &[key], Auth::EmptyPassword, |w| {
        w.tpm2b(nonce).u16(ALG_NULL);
        encode_selections(w, &[selection]);
    })
}

/// The output of TPM2_Quote, marshalled.
#[derive(Debug, PartialEq, Eq)]
pub struct SignedAttest {
    /// The TPMS_ATTEST (the TPM2B_ATTEST contents).
    pub attest: Vec<u8>,
    /// The TPMT_SIGNATURE.
    pub signature: Vec<u8>,
}

/// The attestation TPM2_Quote signed, and its signature.
pub fn parse_quote(response: &[u8]) -> Result<SignedAttest, TpmError> {
    let mut r = marshal::response(response, 0)?.params;
    let attest = r.tpm2b()?;
    // The signature is the last parameter: keep its marshalled form, but check its shape.
    let signature = r.clone().rest();
    if r.u16()? != ALG_ECDSA || r.u16()? != ALG_SHA256 {
        return Err(TpmError::Malformed("quote signature is not ECDSA-SHA256"));
    }
    r.tpm2b()?;
    r.tpm2b()?;
    r.finish()?;
    Ok(SignedAttest {
        attest: attest.to_vec(),
        signature: signature.to_vec(),
    })
}

/// TPM2_FlushContext.
#[must_use]
pub fn flush_context(handle: u32) -> Vec<u8> {
    // The handle is a parameter, not in the handle area: it needs no authorization.
    marshal::command(CC_FLUSH_CONTEXT, &[], Auth::None, |w| {
        w.u32(handle);
    })
}

/// The response of a command without output parameters (TPM2_PolicyPCR, TPM2_FlushContext).
pub fn parse_empty(response: &[u8]) -> Result<(), TpmError> {
    marshal::response(response, 0)?.params.finish()
}

/// The fields of a quote's TPMS_ATTEST a verifier (or trust-controller itself) checks.
#[derive(Debug, PartialEq, Eq)]
pub struct QuoteInfo<'attest> {
    /// Name of the signing key.
    pub signer: &'attest [u8],
    /// The qualifying data (nonce).
    pub extra_data: &'attest [u8],
    /// The quoted PCRs.
    pub selections: Vec<PcrSelection>,
    /// Hash (with the signing scheme's algorithm) of the selected PCR values.
    pub pcr_digest: &'attest [u8],
}

/// The fields of a quote's TPMS_ATTEST, checking it is a quote generated by the TPM.
pub fn parse_quote_info(attest: &[u8]) -> Result<QuoteInfo<'_>, TpmError> {
    let mut r = Reader::new(attest);
    if r.u32()? != TPM_GENERATED {
        return Err(TpmError::Malformed("attestation not generated by the TPM"));
    }
    if r.u16()? != ST_ATTEST_QUOTE {
        return Err(TpmError::Malformed("attestation is not a quote"));
    }
    let signer = r.tpm2b()?;
    let extra_data = r.tpm2b()?;
    // clockInfo (clock, resetCount, restartCount, safe), firmwareVersion.
    r.take(8 + 4 + 4 + 1 + 8)?;
    let selections = decode_selections(&mut r)?;
    let pcr_digest = r.tpm2b()?;
    r.finish()?;
    Ok(QuoteInfo {
        signer,
        extra_data,
        selections,
        pcr_digest,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const POLICY_PCR11_ZEROS: &str =
        "fd32fa22c52cfc8e1a0c29eb38519f87084cab0b04b0d8f020a4d38b2f4e223e";

    const SHA256_PCRS_0_1_7: PcrSelection = PcrSelection {
        hash: ALG_SHA256,
        mask: 0b1000_0011,
    };

    #[test]
    fn pcr_read_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x01, 0, 0, 0, 0x14, 0, 0, 0x01, 0x7e, // header (20 bytes)
            0, 0, 0, 1,                                  // TPML_PCR_SELECTION.count
            0, 0x0b, 3, 0x83, 0, 0,                      // sha256: PCRs 0, 1, 7
        ];
        assert_eq!(pcr_read(SHA256_PCRS_0_1_7), expected);
        let high = PcrSelection {
            hash: ALG_SHA1,
            mask: 1 << 23 | 1 << 8,
        };
        assert_eq!(pcr_read(high)[14..], [0, 0x04, 3, 0, 0x01, 0x80]);
    }

    #[test]
    fn create_primary_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x02, 0, 0, 0, 0x41, 0, 0, 0x01, 0x31, // header (65 bytes)
            0x40, 0, 0, 0x0b,                            // TPM_RH_ENDORSEMENT
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 4, 0, 0, 0, 0,                            // inSensitive: empty userAuth, data
            0, 0x18,                                     // inPublic (24 bytes)
            0, 0x23, 0, 0x0b,                            //   ECC, nameAlg SHA256
            0, 0x05, 0, 0x72,                            //   objectAttributes
            0, 0,                                        //   authPolicy
            0, 0x10,                                     //   symmetric: NULL
            0, 0x18, 0, 0x0b,                            //   scheme: ECDSA-SHA256
            0, 0x03,                                     //   curve: NIST P-256
            0, 0x10,                                     //   kdf: NULL
            0, 0, 0, 0,                                  //   unique: empty point
            0, 0,                                        // outsideInfo
            0, 0, 0, 0,                                  // creationPCR
        ];
        assert_eq!(create_primary(RH_ENDORSEMENT, &ak_template()), expected);
    }

    #[test]
    fn create_primary_srk_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x02, 0, 0, 0, 0x43, 0, 0, 0x01, 0x31, // header (67 bytes)
            0x40, 0, 0, 0x01,                            // TPM_RH_OWNER
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 4, 0, 0, 0, 0,                            // inSensitive: empty userAuth, data
            0, 0x1a,                                     // inPublic (26 bytes)
            0, 0x23, 0, 0x0b,                            //   ECC, nameAlg SHA256
            0, 0x03, 0x04, 0x72,                         //   objectAttributes
            0, 0,                                        //   authPolicy
            0, 0x06, 0, 0x80, 0, 0x43,                   //   symmetric: AES-128-CFB
            0, 0x10,                                     //   scheme: NULL
            0, 0x03,                                     //   curve: NIST P-256
            0, 0x10,                                     //   kdf: NULL
            0, 0, 0, 0,                                  //   unique: empty point
            0, 0,                                        // outsideInfo
            0, 0, 0, 0,                                  // creationPCR
        ];
        assert_eq!(create_primary(RH_OWNER, &srk_template()), expected);
    }

    #[test]
    fn create_sealed_object_command_bytes() {
        #[rustfmt::skip]
        let mut expected = vec![
            0x80, 0x02, 0, 0, 0, 0x5b, 0, 0, 0x01, 0x53, // header (91 bytes)
            0x80, 0, 0, 0,                               // parentHandle
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 8, 0, 0, 0, 4, b'k', b'e', b'y', b'!',    // inSensitive: empty userAuth, data
            0, 0x2e,                                     // inPublic (46 bytes)
            0, 0x08, 0, 0x0b,                            //   KEYEDHASH, nameAlg SHA256
            0, 0, 0x04, 0x12,                            //   objectAttributes
            0, 0x20,                                     //   authPolicy (32 bytes)
        ];
        expected.extend([0xab; 32]);
        #[rustfmt::skip]
        expected.extend([
            0, 0x10,                                     //   scheme: NULL
            0, 0,                                        //   unique: empty
            0, 0,                                        // outsideInfo
            0, 0, 0, 0,                                  // creationPCR
        ]);
        assert_eq!(
            create(0x8000_0000, b"key!", &sealed_template(&[0xab; 32])),
            expected
        );
    }

    #[test]
    fn policy_session_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x01, 0, 0, 0, 0x1f, 0, 0, 0x01, 0x76, // header (31 bytes)
            0x40, 0, 0, 0x07, 0x40, 0, 0, 0x07,          // tpmKey, bind: TPM_RH_NULL
            0, 4, 1, 2, 3, 4,                            // nonceCaller
            0, 0,                                        // encryptedSalt
            0x01,                                        // TPM_SE_POLICY
            0, 0x10,                                     // symmetric: NULL
            0, 0x0b,                                     // authHash: SHA256
        ];
        assert_eq!(start_policy_session(&[1, 2, 3, 4]), expected);

        let pcr11 = PcrSelection {
            hash: ALG_SHA256,
            mask: 1 << 11,
        };
        #[rustfmt::skip]
        let expected = [
            0x80, 0x01, 0, 0, 0, 0x1a, 0, 0, 0x01, 0x7f, // header (26 bytes)
            0x03, 0, 0, 0,                               // policySession
            0, 0,                                        // pcrDigest: the current values
            0, 0, 0, 1, 0, 0x0b, 3, 0, 0x08, 0,          // pcrs: sha256, PCR 11
        ];
        assert_eq!(policy_pcr(0x0300_0000, pcr11), expected);
    }

    #[test]
    fn load_and_unseal_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x02, 0, 0, 0, 0x22, 0, 0, 0x01, 0x57, // header (34 bytes)
            0x80, 0, 0, 0,                               // parentHandle
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 2, 0xa, 0xb, 0, 1, 0xc,                   // inPrivate, inPublic
        ];
        assert_eq!(load(0x8000_0000, &[0xa, 0xb], &[0xc]), expected);

        #[rustfmt::skip]
        let expected = [
            0x80, 0x02, 0, 0, 0, 0x1d, 0, 0, 0x01, 0x5e, // header (29 bytes)
            0x80, 0, 0, 1,                               // itemHandle
            0, 0, 0, 0x0b,                               // authorizationSize
            0x03, 0, 0, 0,                               // policy session
            0, 2, b'n', b'c',                            // nonceCaller
            0,                                           // sessionAttributes
            0, 0,                                        // hmac: none
        ];
        assert_eq!(unseal(0x8000_0001, 0x0300_0000, b"nc"), expected);
    }

    #[test]
    fn parses_sealing_responses() {
        let mut params = Writer::default();
        params.tpm2b(b"private").tpm2b(b"public").bytes(&[0; 9]);
        let rsp = marshal::test_response(&[], &params.into_bytes(), true);
        let sealed = Sealed {
            private: b"private".to_vec(),
            public: b"public".to_vec(),
        };
        assert_eq!(parse_create(&rsp).unwrap(), sealed);

        let mut params = Writer::default();
        params.tpm2b(b"name");
        let rsp = marshal::test_response(&[0x8000_0001], &params.into_bytes(), true);
        assert_eq!(parse_handle(&rsp).unwrap(), 0x8000_0001);

        let mut params = Writer::default();
        params.tpm2b(&[7; 16]);
        let rsp = marshal::test_response(&[0x0300_0000], &params.into_bytes(), false);
        assert_eq!(parse_handle(&rsp).unwrap(), 0x0300_0000);

        let mut params = Writer::default();
        params.tpm2b(b"secret");
        let rsp = marshal::test_response(&[], &params.into_bytes(), true);
        assert_eq!(parse_unseal(&rsp).unwrap(), b"secret");
    }

    /// TPM2_PolicyPCR on sha256:11 when PCR 11 is all zeros, as computed by a TPM (swtpm, through
    /// a trial session and TPM2_PolicyGetDigest).
    #[test]
    fn policy_pcr_digest_known_answer() {
        let pcr11 = PcrSelection {
            hash: ALG_SHA256,
            mask: 1 << 11,
        };
        let digest = policy_pcr_digest(pcr11, &Sha256::digest([0; 32]));
        assert_eq!(hex::encode(digest), POLICY_PCR11_ZEROS);
    }

    #[test]
    fn quote_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x02, 0, 0, 0, 0x2d, 0, 0, 0x01, 0x58, // header (45 bytes)
            0x80, 0, 0, 0,                               // signHandle
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 4, b'n', b'o', b'n', b'c',                // qualifyingData
            0, 0x10,                                     // inScheme: NULL
            0, 0, 0, 1, 0, 0x0b, 3, 0x83, 0, 0,          // PCRselect
        ];
        assert_eq!(quote(0x8000_0000, b"nonc", SHA256_PCRS_0_1_7), expected);
    }

    #[test]
    fn flush_context_command_bytes() {
        assert_eq!(
            flush_context(0x8000_0001),
            [0x80, 0x01, 0, 0, 0, 0x0e, 0, 0, 0x01, 0x65, 0x80, 0, 0, 1]
        );
    }

    #[test]
    fn parses_partial_pcr_read() {
        let mut params = vec![
            0, 0, 0, 0x2a, // pcrUpdateCounter
            0, 0, 0, 1, 0, 0x0b, 3, 0x03, 0, 0, // sha256: PCRs 0, 1 (of 0, 1, 7)
            0, 0, 0, 2, // TPML_DIGEST.count
        ];
        for fill in [0x11, 0x22] {
            params.extend([0, 32]);
            params.extend([fill; 32]);
        }
        let mut rsp = marshal::test_response(&[], &params, false);

        let out = parse_pcr_read(&rsp).unwrap();
        assert_eq!(out.update_counter, 42);
        assert_eq!(
            out.selections,
            [PcrSelection {
                hash: ALG_SHA256,
                mask: 0b11
            }]
        );
        assert_eq!(out.selections[0].indices().collect::<Vec<_>>(), [0, 1]);
        assert_eq!(out.digests, [&[0x11; 32][..], &[0x22; 32][..]]);

        rsp.push(0);
        assert!(parse_pcr_read(&rsp).is_err());
    }

    #[test]
    fn parses_create_primary() {
        #[rustfmt::skip]
        let rsp = [
            0x80, 0x02, 0, 0, 0, 0x23, 0, 0, 0, 0, // header (35 bytes)
            0x80, 0, 0, 0,                         // objectHandle
            0, 0, 0, 0x0c,                         // parameterSize
            0, 3, 0xa, 0xb, 0xc,                   // outPublic
            0, 0, 0, 0, 0, 0, 0,                   // (rest of the parameters, truncated)
            0, 0, 1, 0, 0,                         // TPMS_AUTH_RESPONSE
        ];
        let primary = Primary {
            handle: 0x8000_0000,
            public: vec![0xa, 0xb, 0xc],
        };
        assert_eq!(parse_create_primary(&rsp).unwrap(), primary);
    }

    #[test]
    fn parses_quote_and_attest() {
        let mut attest = Writer::default();
        attest
            .u32(TPM_GENERATED)
            .u16(ST_ATTEST_QUOTE)
            .tpm2b(b"signer")
            .tpm2b(b"nonce");
        attest.bytes(&[0; 25]);
        encode_selections(&mut attest, &[SHA256_PCRS_0_1_7]);
        attest.tpm2b(&[0xd; 32]);
        let attest = attest.into_bytes();

        let mut signature = Writer::default();
        signature
            .u16(ALG_ECDSA)
            .u16(ALG_SHA256)
            .tpm2b(&[1; 32])
            .tpm2b(&[2; 32]);
        let signature = signature.into_bytes();

        let mut params = Writer::default();
        params.tpm2b(&attest).bytes(&signature);
        let rsp = marshal::test_response(&[], &params.into_bytes(), true);

        let signed = parse_quote(&rsp).unwrap();
        assert_eq!(
            signed,
            SignedAttest {
                attest: attest.clone(),
                signature
            }
        );
        let info = parse_quote_info(&signed.attest).unwrap();
        assert_eq!(
            info,
            QuoteInfo {
                signer: b"signer",
                extra_data: b"nonce",
                selections: vec![SHA256_PCRS_0_1_7],
                pcr_digest: &[0xd; 32],
            }
        );
    }

    #[test]
    fn rejects_foreign_attestations() {
        let mut attest = Writer::default();
        attest.u32(TPM_GENERATED).u16(0x8017); // TPM_ST_ATTEST_CERTIFY
        assert!(matches!(
            parse_quote_info(&attest.into_bytes()),
            Err(TpmError::Malformed("attestation is not a quote"))
        ));
        assert!(parse_quote_info(&[0; 6]).is_err());
    }
}

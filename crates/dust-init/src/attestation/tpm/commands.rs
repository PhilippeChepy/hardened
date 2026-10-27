//! The TPM 2.0 commands dust-init issues (TPM 2.0 Part 3), as pure encode/decode functions.

use super::TpmError;
use super::marshal::{self, Auth, Reader, Writer};

const CC_CREATE_PRIMARY: u32 = 0x0000_0131;
const CC_CREATE: u32 = 0x0000_0153;
const CC_LOAD: u32 = 0x0000_0157;
const CC_QUOTE: u32 = 0x0000_0158;
const CC_UNSEAL: u32 = 0x0000_015E;
const CC_FLUSH_CONTEXT: u32 = 0x0000_0165;
const CC_START_AUTH_SESSION: u32 = 0x0000_0176;
const CC_PCR_READ: u32 = 0x0000_017E;
const CC_POLICY_PCR: u32 = 0x0000_017F;

pub const RH_OWNER: u32 = 0x4000_0001;
const RH_NULL: u32 = 0x4000_0007;
pub const RH_ENDORSEMENT: u32 = 0x4000_000B;

pub const ALG_SHA1: u16 = 0x0004;
pub const ALG_SHA256: u16 = 0x000B;
pub const ALG_SHA384: u16 = 0x000C;
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
const RESTRICTED: u32 = 1 << 16;
const DECRYPT: u32 = 1 << 17;
const SIGN: u32 = 1 << 18;

/// TPM_SE_POLICY.
const SE_POLICY: u8 = 0x01;

/// TPM_GENERATED_VALUE: "\xffTCG", proves a TPMS_ATTEST was produced by the TPM.
const TPM_GENERATED: u32 = 0xFF54_4347;
const ST_ATTEST_QUOTE: u16 = 0x8018;

/// One TPMS_PCR_SELECTION: a bank and a bitmap of its PCRs (bit `i` is PCR `i`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PcrSelection {
    pub hash: u16,
    pub mask: u32,
}

impl PcrSelection {
    /// PC Client TPMs have 24 PCRs, selected with 3 bytes.
    const SIZE_OF_SELECT: u8 = 3;

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
        let mask = select.iter().rev().fold(0, |mask, &b| mask << 8 | u32::from(b));
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
pub fn pcr_read(selection: PcrSelection) -> Vec<u8> {
    marshal::command(CC_PCR_READ, &[], Auth::None, |w| encode_selections(w, &[selection]))
}

#[derive(Debug)]
pub struct PcrReadOut<'a> {
    pub update_counter: u32,
    /// What the TPM actually read: possibly a subset of the request.
    pub selections: Vec<PcrSelection>,
    /// One digest per selected PCR, in selection order.
    pub digests: Vec<&'a [u8]>,
}

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

/// TPMT_PUBLIC of the storage key sealed objects are created under: the TCG's ECC P-256 storage
/// root key template (restricted decryption key, AES-128-CFB for its children), with empty auth
/// and no dictionary-attack protection.
pub fn srk_template() -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(ALG_ECC)
        .u16(ALG_SHA256)
        .u32(FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | NO_DA | RESTRICTED | DECRYPT)
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
pub fn create_primary(hierarchy: u32, template: &[u8]) -> Vec<u8> {
    marshal::command(CC_CREATE_PRIMARY, &[hierarchy], Auth::Password(&[]), |w| {
        w.sized(|w| {
            // TPMS_SENSITIVE_CREATE: userAuth, data.
            w.tpm2b(&[]).tpm2b(&[]);
        })
        .tpm2b(template)
        .tpm2b(&[]); // outsideInfo
        encode_selections(w, &[]); // creationPCR
    })
}

/// The transient handle and TPMT_PUBLIC (the TPM2B_PUBLIC contents) of the created key.
pub fn parse_create_primary(response: &[u8]) -> Result<(u32, Vec<u8>), TpmError> {
    let marshal::Response {
        mut handles,
        mut params,
    } = marshal::response(response, 1)?;
    let handle = handles.u32()?;
    let public = params.tpm2b()?;
    // creationData, creationHash, creationTicket and name follow; dust-init needs none of them.
    Ok((handle, public.to_vec()))
}

/// TPM2_Create of a data object holding `data` under `parent` (authorized with an empty
/// password).
pub fn create(parent: u32, data: &[u8], template: &[u8]) -> Vec<u8> {
    marshal::command(CC_CREATE, &[parent], Auth::Password(&[]), |w| {
        w.sized(|w| {
            // TPMS_SENSITIVE_CREATE: userAuth, data.
            w.tpm2b(&[]).tpm2b(data);
        })
        .tpm2b(template)
        .tpm2b(&[]); // outsideInfo
        encode_selections(w, &[]); // creationPCR
    })
}

/// The TPM2B_PRIVATE and TPM2B_PUBLIC contents of the created object.
pub fn parse_create(response: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
    let mut params = marshal::response(response, 0)?.params;
    let private = params.tpm2b()?;
    let public = params.tpm2b()?;
    // creationData, creationHash and creationTicket follow; dust-init needs none of them.
    Ok((private.to_vec(), public.to_vec()))
}

/// TPM2_Load of an object created under `parent` (authorized with an empty password).
pub fn load(parent: u32, private: &[u8], public: &[u8]) -> Vec<u8> {
    marshal::command(CC_LOAD, &[parent], Auth::Password(&[]), |w| {
        w.tpm2b(private).tpm2b(public);
    })
}

/// The transient handle of the loaded object.
pub fn parse_load(response: &[u8]) -> Result<u32, TpmError> {
    let marshal::Response { mut handles, .. } = marshal::response(response, 1)?;
    handles.u32()
}

/// TPM2_StartAuthSession of an unbound, unsalted policy session hashing with SHA-256.
pub fn start_policy_session(nonce: &[u8]) -> Vec<u8> {
    marshal::command(CC_START_AUTH_SESSION, &[RH_NULL, RH_NULL], Auth::None, |w| {
        w.tpm2b(nonce)
            .tpm2b(&[]) // encryptedSalt
            .u8(SE_POLICY)
            .u16(ALG_NULL) // symmetric: no parameter encryption
            .u16(ALG_SHA256);
    })
}

/// The handle of the started session.
pub fn parse_start_auth_session(response: &[u8]) -> Result<u32, TpmError> {
    let marshal::Response { mut handles, .. } = marshal::response(response, 1)?;
    handles.u32()
}

/// TPM2_PolicyPCR over `selection` at their current values (an empty `pcrDigest`).
pub fn policy_pcr(session: u32, selection: PcrSelection) -> Vec<u8> {
    marshal::command(CC_POLICY_PCR, &[session], Auth::None, |w| {
        w.tpm2b(&[]);
        encode_selections(w, &[selection]);
    })
}

pub fn parse_policy_pcr(response: &[u8]) -> Result<(), TpmError> {
    marshal::response(response, 0)?.params.finish()
}

/// The policy digest TPM2_PolicyPCR leaves in a fresh SHA-256 session for `selection` at
/// values whose concatenation hashes to `pcr_digest` (TPM 2.0 Part 3, §23.7).
pub fn policy_pcr_digest(selection: PcrSelection, pcr_digest: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
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
pub fn unseal(object: u32, session: u32, nonce: &[u8]) -> Vec<u8> {
    marshal::command(CC_UNSEAL, &[object], Auth::Policy { session, nonce }, |_| {})
}

/// The unsealed data.
pub fn parse_unseal(response: &[u8]) -> Result<Vec<u8>, TpmError> {
    let mut params = marshal::response(response, 0)?.params;
    let data = params.tpm2b()?.to_vec();
    params.finish()?;
    Ok(data)
}

/// TPM2_Quote with `key` (authorized with an empty password) and its own signing scheme.
pub fn quote(key: u32, nonce: &[u8], selection: PcrSelection) -> Vec<u8> {
    marshal::command(CC_QUOTE, &[key], Auth::Password(&[]), |w| {
        w.tpm2b(nonce).u16(ALG_NULL);
        encode_selections(w, &[selection]);
    })
}

/// The TPMS_ATTEST (the TPM2B_ATTEST contents) and the marshalled TPMT_SIGNATURE.
pub fn parse_quote(response: &[u8]) -> Result<(Vec<u8>, Vec<u8>), TpmError> {
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
    Ok((attest.to_vec(), signature.to_vec()))
}

/// TPM2_FlushContext.
pub fn flush_context(handle: u32) -> Vec<u8> {
    // The handle is a parameter, not in the handle area: it needs no authorization.
    marshal::command(CC_FLUSH_CONTEXT, &[], Auth::None, |w| {
        w.u32(handle);
    })
}

pub fn parse_flush_context(response: &[u8]) -> Result<(), TpmError> {
    marshal::response(response, 0)?.params.finish()
}

/// The fields of a quote's TPMS_ATTEST a verifier (or dust-init itself) checks.
#[derive(Debug, PartialEq, Eq)]
pub struct QuoteInfo<'a> {
    /// Name of the signing key.
    pub signer: &'a [u8],
    /// The qualifying data (nonce).
    pub extra_data: &'a [u8],
    pub selections: Vec<PcrSelection>,
    /// Hash (with the signing scheme's algorithm) of the selected PCR values.
    pub pcr_digest: &'a [u8],
}

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

    const POLICY_PCR11_ZEROS: &str = "fd32fa22c52cfc8e1a0c29eb38519f87084cab0b04b0d8f020a4d38b2f4e223e";

    const SHA256_PCRS_0_1_7: PcrSelection = PcrSelection {
        hash: ALG_SHA256,
        mask: 0b1000_0011,
    };

    #[test]
    fn pcr_read_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x01, 0, 0, 0, 0x14, 0, 0, 0x01, 0x7E, // header (20 bytes)
            0, 0, 0, 1,                                  // TPML_PCR_SELECTION.count
            0, 0x0B, 3, 0x83, 0, 0,                      // sha256: PCRs 0, 1, 7
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
            0x40, 0, 0, 0x0B,                            // TPM_RH_ENDORSEMENT
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 4, 0, 0, 0, 0,                            // inSensitive: empty userAuth, data
            0, 0x18,                                     // inPublic (24 bytes)
            0, 0x23, 0, 0x0B,                            //   ECC, nameAlg SHA256
            0, 0x05, 0, 0x72,                            //   objectAttributes
            0, 0,                                        //   authPolicy
            0, 0x10,                                     //   symmetric: NULL
            0, 0x18, 0, 0x0B,                            //   scheme: ECDSA-SHA256
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
            0, 0x1A,                                     // inPublic (26 bytes)
            0, 0x23, 0, 0x0B,                            //   ECC, nameAlg SHA256
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
            0x80, 0x02, 0, 0, 0, 0x5B, 0, 0, 0x01, 0x53, // header (91 bytes)
            0x80, 0, 0, 0,                               // parentHandle
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 8, 0, 0, 0, 4, b'k', b'e', b'y', b'!',    // inSensitive: empty userAuth, data
            0, 0x2E,                                     // inPublic (46 bytes)
            0, 0x08, 0, 0x0B,                            //   KEYEDHASH, nameAlg SHA256
            0, 0, 0x04, 0x12,                            //   objectAttributes
            0, 0x20,                                     //   authPolicy (32 bytes)
        ];
        expected.extend([0xAB; 32]);
        #[rustfmt::skip]
        expected.extend([
            0, 0x10,                                     //   scheme: NULL
            0, 0,                                        //   unique: empty
            0, 0,                                        // outsideInfo
            0, 0, 0, 0,                                  // creationPCR
        ]);
        assert_eq!(create(0x8000_0000, b"key!", &sealed_template(&[0xAB; 32])), expected);
    }

    #[test]
    fn policy_session_command_bytes() {
        #[rustfmt::skip]
        let expected = [
            0x80, 0x01, 0, 0, 0, 0x1F, 0, 0, 0x01, 0x76, // header (31 bytes)
            0x40, 0, 0, 0x07, 0x40, 0, 0, 0x07,          // tpmKey, bind: TPM_RH_NULL
            0, 4, 1, 2, 3, 4,                            // nonceCaller
            0, 0,                                        // encryptedSalt
            0x01,                                        // TPM_SE_POLICY
            0, 0x10,                                     // symmetric: NULL
            0, 0x0B,                                     // authHash: SHA256
        ];
        assert_eq!(start_policy_session(&[1, 2, 3, 4]), expected);

        let pcr11 = PcrSelection {
            hash: ALG_SHA256,
            mask: 1 << 11,
        };
        #[rustfmt::skip]
        let expected = [
            0x80, 0x01, 0, 0, 0, 0x1A, 0, 0, 0x01, 0x7F, // header (26 bytes)
            0x03, 0, 0, 0,                               // policySession
            0, 0,                                        // pcrDigest: the current values
            0, 0, 0, 1, 0, 0x0B, 3, 0, 0x08, 0,          // pcrs: sha256, PCR 11
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
            0, 2, 0xA, 0xB, 0, 1, 0xC,                   // inPrivate, inPublic
        ];
        assert_eq!(load(0x8000_0000, &[0xA, 0xB], &[0xC]), expected);

        #[rustfmt::skip]
        let expected = [
            0x80, 0x02, 0, 0, 0, 0x1B, 0, 0, 0x01, 0x5E, // header (27 bytes)
            0x80, 0, 0, 1,                               // itemHandle
            0, 0, 0, 9, 0x03, 0, 0, 0, 0, 0, 0, 0, 0,    // policy session, no nonce, no hmac
        ];
        assert_eq!(unseal(0x8000_0001, 0x0300_0000, &[]), expected);
    }

    #[test]
    fn parses_sealing_responses() {
        let mut params = Writer::default();
        params.tpm2b(b"private").tpm2b(b"public").bytes(&[0; 9]);
        let rsp = marshal::test_response(&[], &params.into_bytes(), true);
        assert_eq!(parse_create(&rsp).unwrap(), (b"private".to_vec(), b"public".to_vec()));

        let mut params = Writer::default();
        params.tpm2b(b"name");
        let rsp = marshal::test_response(&[0x8000_0001], &params.into_bytes(), true);
        assert_eq!(parse_load(&rsp).unwrap(), 0x8000_0001);

        let mut params = Writer::default();
        params.tpm2b(&[7; 16]);
        let rsp = marshal::test_response(&[0x0300_0000], &params.into_bytes(), false);
        assert_eq!(parse_start_auth_session(&rsp).unwrap(), 0x0300_0000);

        let mut params = Writer::default();
        params.tpm2b(b"secret");
        let rsp = marshal::test_response(&[], &params.into_bytes(), true);
        assert_eq!(parse_unseal(&rsp).unwrap(), b"secret");
    }

    /// TPM2_PolicyPCR on sha256:11 when PCR 11 is all zeros, as computed by a TPM (swtpm, through
    /// a trial session and TPM2_PolicyGetDigest).
    #[test]
    fn policy_pcr_digest_known_answer() {
        use sha2::{Digest, Sha256};
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
            0x80, 0x02, 0, 0, 0, 0x2D, 0, 0, 0x01, 0x58, // header (45 bytes)
            0x80, 0, 0, 0,                               // signHandle
            0, 0, 0, 9, 0x40, 0, 0, 0x09, 0, 0, 0, 0, 0, // TPM_RS_PW, empty password
            0, 4, b'n', b'o', b'n', b'c',                // qualifyingData
            0, 0x10,                                     // inScheme: NULL
            0, 0, 0, 1, 0, 0x0B, 3, 0x83, 0, 0,          // PCRselect
        ];
        assert_eq!(quote(0x8000_0000, b"nonc", SHA256_PCRS_0_1_7), expected);
    }

    #[test]
    fn flush_context_command_bytes() {
        assert_eq!(
            flush_context(0x8000_0001),
            [0x80, 0x01, 0, 0, 0, 0x0E, 0, 0, 0x01, 0x65, 0x80, 0, 0, 1]
        );
    }

    #[test]
    fn parses_partial_pcr_read() {
        let mut params = vec![
            0, 0, 0, 0x2A, // pcrUpdateCounter
            0, 0, 0, 1, 0, 0x0B, 3, 0x03, 0, 0, // sha256: PCRs 0, 1 (of 0, 1, 7)
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
            0, 0, 0, 0x0C,                         // parameterSize
            0, 3, 0xA, 0xB, 0xC,                   // outPublic
            0, 0, 0, 0, 0, 0, 0,                   // (rest of the parameters, truncated)
            0, 0, 1, 0, 0,                         // TPMS_AUTH_RESPONSE
        ];
        assert_eq!(parse_create_primary(&rsp).unwrap(), (0x8000_0000, vec![0xA, 0xB, 0xC]));
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
        attest.tpm2b(&[0xD; 32]);
        let attest = attest.into_bytes();

        let mut signature = Writer::default();
        signature.u16(ALG_ECDSA).u16(ALG_SHA256).tpm2b(&[1; 32]).tpm2b(&[2; 32]);
        let signature = signature.into_bytes();

        let mut params = Writer::default();
        params.tpm2b(&attest).bytes(&signature);
        let rsp = marshal::test_response(&[], &params.into_bytes(), true);

        let (got_attest, got_signature) = parse_quote(&rsp).unwrap();
        assert_eq!((&got_attest, &got_signature), (&attest, &signature));
        let info = parse_quote_info(&got_attest).unwrap();
        assert_eq!(
            info,
            QuoteInfo {
                signer: b"signer",
                extra_data: b"nonce",
                selections: vec![SHA256_PCRS_0_1_7],
                pcr_digest: &[0xD; 32],
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

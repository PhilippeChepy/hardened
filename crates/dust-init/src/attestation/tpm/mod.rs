//! TPM 2.0 commands over `/dev/tpmrm0`: attestation (PCR reads, quotes) and sealing secrets to
//! PCR values (the state partition's key).
//!
//! The kernel resource manager takes one whole command per `write` and returns the whole
//! response on the next `read`; it also virtualizes transient handles per open file, so the
//! attestation key lives exactly as long as this [`Tpm`] (and whatever a failure leaves loaded is
//! flushed when it is dropped).

mod commands;
mod marshal;
mod rc;
#[cfg(test)]
mod tests;

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::Path;
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use commands::PcrSelection;
pub use rc::ResponseCode;

/// PC Client TPMs have PCRs 0 to 23.
const PCR_COUNT: u32 = 24;
/// Largest TPM2B_DATA a TPM accepts as qualifying data (a SHA-512 digest).
pub const MAX_NONCE_LEN: usize = 64;
/// The kernel's TPM_BUFSIZE: no command or response is larger.
const MAX_RESPONSE_LEN: usize = 4096;
/// Bounds the retries when PCRs are extended while being read or quoted.
const PCR_ATTEMPTS: usize = 4;
/// Bounds the retries on TPM_RC_RETRY, TPM_RC_YIELDED and TPM_RC_TESTING.
const BUSY_ATTEMPTS: u32 = 5;

#[derive(Debug, thiserror::Error)]
pub enum TpmError {
    #[error("tpm i/o: {0}")]
    Io(#[from] io::Error),
    #[error("tpm returned {0}")]
    Response(ResponseCode),
    #[error("malformed tpm response: {0}")]
    Malformed(&'static str),
    #[error("invalid PCR index {0}, expected 0 to 23")]
    InvalidPcr(u32),
    #[error("no PCR selected")]
    NoPcrSelected,
    #[error("nonce of {0} bytes, at most {MAX_NONCE_LEN} are allowed")]
    NonceTooLong(usize),
    #[error("PCR {pcr} is not available in the {bank} bank")]
    PcrUnavailable { bank: HashAlg, pcr: u32 },
    #[error("PCRs kept changing while being read or quoted")]
    PcrsChanged,
    #[error("quote does not match its request: {0}")]
    QuoteMismatch(&'static str),
}

impl TpmError {
    /// Whether the TPM refused a sealed object because it is not for this TPM in this state:
    /// sealed by another TPM, or before its owner hierarchy was cleared (it does not load), or to
    /// other PCR values (the policy fails). Asking again cannot succeed.
    pub fn is_sealed_elsewhere(&self) -> bool {
        const POLICY_FAIL: u16 = 0x09D;
        const INTEGRITY: u16 = 0x09F;
        const BINDING: u16 = 0x0A5;
        matches!(self, Self::Response(rc) if matches!(rc.format_one(), Some(POLICY_FAIL | INTEGRITY | BINDING)))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
}

impl HashAlg {
    /// TPM_ALG_ID.
    fn id(self) -> u16 {
        match self {
            Self::Sha1 => commands::ALG_SHA1,
            Self::Sha256 => commands::ALG_SHA256,
            Self::Sha384 => commands::ALG_SHA384,
        }
    }

    pub fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
        })
    }
}

#[derive(Debug, Clone)]
pub struct Quote {
    /// Marshalled TPMS_ATTEST.
    pub attest: Vec<u8>,
    /// Marshalled TPMT_SIGNATURE.
    pub signature: Vec<u8>,
    /// Marshalled TPMT_PUBLIC of the attestation key.
    pub ak_public: Vec<u8>,
    /// The quoted PCR values, by ascending index: their SHA-256 over the concatenation is the
    /// quote's `pcrDigest`.
    pub pcrs: Vec<(u32, Vec<u8>)>,
}

/// A secret sealed by [`Tpm::seal`]: the TPM2B_PRIVATE and TPM2B_PUBLIC contents of a data object
/// of the storage key. Not secret: only the TPM that sealed it unseals it, and only in the PCR
/// state it was sealed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub private: Vec<u8>,
    pub public: Vec<u8>,
}

impl Sealed {
    /// The marshalled TPM2B_PRIVATE then TPM2B_PUBLIC (the layout of systemd's `tpm2-blob`).
    pub fn to_blob(&self) -> Vec<u8> {
        let mut w = marshal::Writer::default();
        w.tpm2b(&self.private).tpm2b(&self.public);
        w.into_bytes()
    }

    pub fn from_blob(blob: &[u8]) -> Result<Self, TpmError> {
        let mut r = marshal::Reader::new(blob);
        let private = r.tpm2b()?.to_vec();
        let public = r.tpm2b()?.to_vec();
        r.finish()?;
        Ok(Self { private, public })
    }
}

/// Sends a marshalled command to a TPM and returns its marshalled response.
pub trait Transport {
    fn transact(&mut self, command: &[u8]) -> io::Result<Vec<u8>>;
}

/// A TPM character device (`/dev/tpmrm0`).
#[derive(Debug)]
struct Device(File);

impl Transport for Device {
    fn transact(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
        // The driver requires the command in a single write.
        let written = retry_interrupted(|| self.0.write(command))?;
        if written != command.len() {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "partial write of a tpm command",
            ));
        }
        let mut response = vec![0; MAX_RESPONSE_LEN];
        let len = retry_interrupted(|| self.0.read(&mut response))?;
        response.truncate(len);
        Ok(response)
    }
}

fn retry_interrupted<T>(mut f: impl FnMut() -> io::Result<T>) -> io::Result<T> {
    loop {
        match f() {
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            result => return result,
        }
    }
}

/// The attestation key, a transient object of this TPM session.
#[derive(Debug)]
struct AttestationKey {
    handle: u32,
    /// TPMT_PUBLIC.
    public: Vec<u8>,
    /// Qualified name (the quotes' `qualifiedSigner`): nameAlg then the digest of the
    /// hierarchy handle and the key's name (nameAlg then the digest of `public`).
    qualified_name: Vec<u8>,
}

/// A handle on the TPM resource manager. Blocking: call from `spawn_blocking`.
pub struct Tpm {
    transport: Box<dyn Transport + Send>,
    ak: Option<AttestationKey>,
}

impl fmt::Debug for Tpm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Tpm")
            .field("ak", &self.ak.as_ref().map(|ak| ak.handle))
            .finish_non_exhaustive()
    }
}

impl Tpm {
    pub const DEVICE: &str = "/dev/tpmrm0";

    /// Opens the TPM, or returns `None` when the machine has none.
    pub fn open(path: &Path) -> Result<Option<Self>, TpmError> {
        match OpenOptions::new().read(true).write(true).open(path) {
            Ok(file) => Ok(Some(Self::with_transport(Device(file)))),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn with_transport(transport: impl Transport + Send + 'static) -> Self {
        Self {
            transport: Box::new(transport),
            ak: None,
        }
    }

    /// Reads PCR values of a bank, by ascending index (duplicates are read once).
    pub fn pcr_read(&mut self, bank: HashAlg, pcrs: &[u32]) -> Result<Vec<(u32, Vec<u8>)>, TpmError> {
        let mask = pcr_mask(pcrs)?;
        if mask == 0 {
            return Ok(Vec::new());
        }
        self.pcr_read_mask(bank, mask)
    }

    /// TPMT_PUBLIC of the attestation key, created on first use.
    #[cfg(test)]
    pub fn ak_public(&mut self) -> Result<&[u8], TpmError> {
        Ok(&self.attestation_key()?.public)
    }

    /// Quotes `pcrs` of `bank` with the attestation key, `nonce` as qualifying data.
    ///
    /// The returned PCR values are checked against the quote's `pcrDigest`, so they are exactly
    /// the quoted ones even if PCRs were extended concurrently.
    pub fn quote(&mut self, nonce: &[u8], bank: HashAlg, pcrs: &[u32]) -> Result<Quote, TpmError> {
        if nonce.len() > MAX_NONCE_LEN {
            return Err(TpmError::NonceTooLong(nonce.len()));
        }
        let selection = PcrSelection {
            hash: bank.id(),
            mask: pcr_mask(pcrs)?,
        };
        if selection.mask == 0 {
            return Err(TpmError::NoPcrSelected);
        }
        let ak = self.attestation_key()?;
        let (handle, ak_name) = (ak.handle, ak.qualified_name.clone());

        for _ in 0..PCR_ATTEMPTS {
            let response = self.execute(&commands::quote(handle, nonce, selection))?;
            let (attest, signature) = commands::parse_quote(&response)?;
            let info = commands::parse_quote_info(&attest)?;
            if info.extra_data != nonce {
                return Err(TpmError::QuoteMismatch("qualifying data is not the nonce"));
            }
            if info.signer != ak_name {
                return Err(TpmError::QuoteMismatch("signer is not the attestation key"));
            }
            if info.selections != [selection] {
                return Err(TpmError::QuoteMismatch("quoted PCRs are not the requested ones"));
            }

            let values = self.pcr_read_mask(bank, selection.mask)?;
            let digest = values
                .iter()
                .fold(Sha256::new(), |h, (_, value)| h.chain_update(value))
                .finalize();
            if digest.as_slice() == info.pcr_digest {
                let ak_public = self.attestation_key()?.public.clone();
                return Ok(Quote {
                    attest,
                    signature,
                    ak_public,
                    pcrs: values,
                });
            }
            tracing::debug!("PCRs extended while quoting, quoting again");
        }
        Err(TpmError::PcrsChanged)
    }

    /// Reads the PCRs of `mask`, which the TPM may return over several partial responses (at
    /// most 8 digests each). Restarts if a PCR is extended between two of them.
    fn pcr_read_mask(&mut self, bank: HashAlg, mask: u32) -> Result<Vec<(u32, Vec<u8>)>, TpmError> {
        'attempt: for _ in 0..PCR_ATTEMPTS {
            let mut values = Vec::with_capacity(mask.count_ones() as usize);
            let mut remaining = mask;
            let mut update_counter = None;
            while remaining != 0 {
                let response = self.execute(&commands::pcr_read(PcrSelection {
                    hash: bank.id(),
                    mask: remaining,
                }))?;
                let out = commands::parse_pcr_read(&response)?;
                if *update_counter.get_or_insert(out.update_counter) != out.update_counter {
                    tracing::debug!("PCRs extended while being read, reading again");
                    continue 'attempt;
                }
                if out.selections.iter().any(|s| s.hash != bank.id()) {
                    return Err(TpmError::Malformed("PCR read from another bank"));
                }
                let indices: Vec<u32> = out.selections.iter().flat_map(|s| s.indices()).collect();
                if indices.len() != out.digests.len() {
                    return Err(TpmError::Malformed("PCR digest count does not match the selection"));
                }
                if indices.is_empty() {
                    // The bank is not allocated, or the TPM lacks these PCRs.
                    return Err(TpmError::PcrUnavailable {
                        bank,
                        pcr: remaining.trailing_zeros(),
                    });
                }
                for (index, digest) in indices.into_iter().zip(out.digests) {
                    if remaining & 1 << index == 0 {
                        return Err(TpmError::Malformed("unrequested PCR read"));
                    }
                    if digest.len() != bank.digest_len() {
                        return Err(TpmError::Malformed("PCR digest of the wrong size"));
                    }
                    remaining &= !(1 << index);
                    values.push((index, digest.to_vec()));
                }
            }
            values.sort_unstable_by_key(|&(index, _)| index);
            return Ok(values);
        }
        Err(TpmError::PcrsChanged)
    }

    /// The policy digest of TPM2_PolicyPCR over `pcrs` of the SHA-256 bank at their current values:
    /// what [`Tpm::seal`] binds a secret to.
    pub fn pcr_policy(&mut self, pcrs: &[u32]) -> Result<[u8; 32], TpmError> {
        let selection = sha256_selection(pcrs)?;
        let values = self.pcr_read_mask(HashAlg::Sha256, selection.mask)?;
        let digest = values
            .iter()
            .fold(Sha256::new(), |h, (_, value)| h.chain_update(value))
            .finalize();
        Ok(commands::policy_pcr_digest(selection, &digest))
    }

    /// Seals `secret` under the storage key of the owner hierarchy, unsealable only through
    /// `policy` (from [`Tpm::pcr_policy`]).
    ///
    /// The secret crosses the TPM interface in clear (no parameter encryption): on a vTPM, the
    /// hypervisor sees it anyway.
    pub fn seal(&mut self, secret: &[u8], policy: &[u8; 32]) -> Result<Sealed, TpmError> {
        let primary = self.storage_key()?;
        let mut command = commands::create(primary, secret, &commands::sealed_template(policy));
        let created = self
            .execute(&command)
            .and_then(|response| commands::parse_create(&response));
        command.zeroize();
        self.flush(primary);
        let (private, public) = created?;
        Ok(Sealed { private, public })
    }

    /// Unseals what [`Tpm::seal`] sealed to the current values of `pcrs` (SHA-256 bank), through a
    /// policy session.
    pub fn unseal(&mut self, sealed: &Sealed, pcrs: &[u32]) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let selection = sha256_selection(pcrs)?;
        let primary = self.storage_key()?;
        let loaded = self
            .execute(&commands::load(primary, &sealed.private, &sealed.public))
            .and_then(|response| commands::parse_load(&response));
        // A loaded object no longer needs its parent.
        self.flush(primary);
        let object = loaded?;
        let unsealed = self.unseal_object(object, selection);
        self.flush(object);
        unsealed
    }

    fn unseal_object(&mut self, object: u32, selection: PcrSelection) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let response = self.execute(&commands::start_policy_session(&nonce()?))?;
        let session = commands::parse_start_auth_session(&response)?;
        let mut unseal = || {
            commands::parse_policy_pcr(&self.execute(&commands::policy_pcr(session, selection))?)?;
            let response = Zeroizing::new(self.execute(&commands::unseal(object, session, &nonce()?))?);
            commands::parse_unseal(&response).map(Zeroizing::new)
        };
        let unsealed = unseal();
        // A successful Unseal flushed the session (continueSession is clear).
        if unsealed.is_err() {
            self.flush(session);
        }
        unsealed
    }

    /// The storage key: a primary key of the owner hierarchy, the same at every boot (derived from
    /// the hierarchy's seed and the template), until the TPM is cleared.
    fn storage_key(&mut self) -> Result<u32, TpmError> {
        let response = self.execute(&commands::create_primary(commands::RH_OWNER, &commands::srk_template()))?;
        Ok(commands::parse_create_primary(&response)?.0)
    }

    /// Flushes a transient object or session, logging a failure: the resource manager flushes
    /// whatever is left when the TPM is closed.
    fn flush(&mut self, handle: u32) {
        let flushed = self
            .execute(&commands::flush_context(handle))
            .and_then(|response| commands::parse_flush_context(&response));
        if let Err(e) = flushed {
            tracing::warn!(handle = format_args!("{handle:#x}"), "flushing a TPM context: {e}");
        }
    }

    /// The attestation key, created as a primary key of the endorsement hierarchy on first use.
    ///
    /// Primary keys derive from the hierarchy seed and the template, so every boot yields the same
    /// key without persisting anything.
    fn attestation_key(&mut self) -> Result<&AttestationKey, TpmError> {
        if self.ak.is_none() {
            let command = commands::create_primary(commands::RH_ENDORSEMENT, &commands::ak_template());
            let response = self.execute(&command)?;
            let (handle, public) = commands::parse_create_primary(&response)?;
            let name_alg = commands::ALG_SHA256.to_be_bytes();
            let name = [&name_alg[..], &Sha256::digest(&public)].concat();
            let qualified = Sha256::new()
                .chain_update(commands::RH_ENDORSEMENT.to_be_bytes())
                .chain_update(name);
            let qualified_name = [&name_alg[..], &qualified.finalize()].concat();
            tracing::debug!(handle = format_args!("{handle:#x}"), "created the attestation key");
            self.ak = Some(AttestationKey {
                handle,
                public,
                qualified_name,
            });
        }
        Ok(self.ak.as_ref().expect("just created"))
    }

    /// Sends a command, re-sending it while the TPM reports itself busy.
    fn execute(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut attempt = 1;
        loop {
            let response = self.transport.transact(command)?;
            match marshal::response_code(&response).map(ResponseCode) {
                Some(rc) if rc.is_retryable() && attempt < BUSY_ATTEMPTS => {
                    tracing::debug!(%rc, attempt, "tpm busy, retrying");
                    std::thread::sleep(Duration::from_millis(20) * attempt);
                    attempt += 1;
                }
                _ => return Ok(response),
            }
        }
    }
}

impl Drop for Tpm {
    fn drop(&mut self) {
        if let Some(ak) = self.ak.take() {
            self.flush(ak.handle);
        }
    }
}

/// A selection of the SHA-256 bank, of at least one PCR.
fn sha256_selection(pcrs: &[u32]) -> Result<PcrSelection, TpmError> {
    let mask = pcr_mask(pcrs)?;
    if mask == 0 {
        return Err(TpmError::NoPcrSelected);
    }
    Ok(PcrSelection {
        hash: commands::ALG_SHA256,
        mask,
    })
}

/// A session nonce: at least 16 bytes for a SHA-256 session.
fn nonce() -> Result<[u8; 16], TpmError> {
    let mut nonce = [0; 16];
    let mut filled = 0;
    while filled < nonce.len() {
        filled += rustix::rand::getrandom(&mut nonce[filled..], rustix::rand::GetRandomFlags::empty())
            .map_err(io::Error::from)?;
    }
    Ok(nonce)
}

/// The bitmap of `pcrs`, rejecting indices past PCR 23.
fn pcr_mask(pcrs: &[u32]) -> Result<u32, TpmError> {
    pcrs.iter().try_fold(0, |mask, &pcr| match pcr {
        0..PCR_COUNT => Ok(mask | 1 << pcr),
        _ => Err(TpmError::InvalidPcr(pcr)),
    })
}

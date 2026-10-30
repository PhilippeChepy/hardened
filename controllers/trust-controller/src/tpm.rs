//! The TPM session over `/dev/tpmrm0`: PCR reads, quotes, sealing and unsealing.
//!
//! Commands are marshalled by hand: no TSS library, no daemon. The kernel resource manager takes
//! one whole command per `write` and returns the whole response on the next `read`; it also
//! virtualizes transient handles per open file, so the attestation key lives exactly as long as
//! this [`Tpm`] (and whatever a failure leaves loaded is flushed when it is dropped).

#[cfg(test)]
mod tests;

use std::fs::OpenOptions;
use std::io;
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

use crate::commands;
use crate::commands::PcrSelection;
use crate::commands::Primary;
use crate::commands::SignedAttest;
use crate::hash_alg::HashAlg;
use crate::marshal;
use crate::response_code::ResponseCode;
use crate::sealed_object::Sealed;
use crate::tpm_error::TpmError;
use crate::transport::Device;
use crate::transport::Transport;

/// PC Client TPMs have PCRs 0 to 23.
pub(crate) const PCR_COUNT: u32 = 24;
/// Largest TPM2B_DATA a TPM accepts as qualifying data (a SHA-512 digest).
pub(crate) const MAX_NONCE_LEN: usize = 64;
/// Bounds the retries when PCRs are extended while being read or quoted.
const PCR_ATTEMPTS: usize = 4;
/// Bounds the retries on TPM_RC_RETRY, TPM_RC_YIELDED and TPM_RC_TESTING.
const BUSY_ATTEMPTS: u32 = 5;

/// A quote of PCRs by the attestation key, and the values it covers.
#[derive(Debug)]
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
    // Type-erased rather than generic: users name `Tpm` alone, whatever its transport.
    transport: Box<dyn Transport + Send>,
    ak: Option<AttestationKey>,
}

impl Tpm {
    /// The resource manager's device.
    pub const DEVICE: &str = "/dev/tpmrm0";

    /// Opens [`Tpm::DEVICE`] (serviced starts trust-controller only when it exists).
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Self::DEVICE)?;
        Ok(Self::with_transport(Device(file)))
    }

    /// A TPM reached through `transport` (a simulator, a test double).
    #[must_use]
    pub fn with_transport(transport: impl Transport + Send + 'static) -> Self {
        Self {
            transport: Box::new(transport),
            ak: None,
        }
    }

    /// Reads PCR values of a bank, by ascending index (duplicates are read once).
    pub fn pcr_read(
        &mut self,
        bank: HashAlg,
        pcrs: &[u32],
    ) -> Result<Vec<(u32, Vec<u8>)>, TpmError> {
        self.pcr_read_mask(bank, pcr_mask(pcrs)?)
    }

    /// Quotes `pcrs` of `bank` with the attestation key, `nonce` as qualifying data.
    ///
    /// The returned PCR values are checked against the quote's `pcrDigest`, so they are exactly
    /// the quoted ones even if PCRs were extended concurrently.
    pub fn quote(&mut self, nonce: &[u8], bank: HashAlg, pcrs: &[u32]) -> Result<Quote, TpmError> {
        if nonce.len() > MAX_NONCE_LEN {
            return Err(TpmError::NonceTooLong(nonce.len()));
        }
        let selection = selection(bank, pcrs)?;
        let ak = self.attestation_key()?;
        // Copied out: the key stays borrowed from `self`, which executes the commands.
        let (handle, ak_name, ak_public) =
            (ak.handle, ak.qualified_name.clone(), ak.public.clone());

        for _ in 0..PCR_ATTEMPTS {
            let response = self.execute(&commands::quote(handle, nonce, selection))?;
            let SignedAttest { attest, signature } = commands::parse_quote(&response)?;
            let info = commands::parse_quote_info(&attest)?;
            if info.extra_data != nonce {
                return Err(TpmError::Malformed(
                    "quote's qualifying data is not the nonce",
                ));
            }
            if info.signer != ak_name {
                return Err(TpmError::Malformed(
                    "quote's signer is not the attestation key",
                ));
            }
            if info.selections != [selection] {
                return Err(TpmError::Malformed(
                    "quoted PCRs are not the requested ones",
                ));
            }

            let values = self.pcr_read_mask(bank, selection.mask)?;
            if pcr_digest(&values) == info.pcr_digest {
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
                    return Err(TpmError::Malformed(
                        "PCR digest count does not match the selection",
                    ));
                }
                if indices.is_empty() {
                    // The bank is not allocated, or the TPM lacks these PCRs.
                    return Err(TpmError::PcrUnavailable {
                        bank,
                        pcr: remaining.trailing_zeros(),
                    });
                }
                let read = indices.into_iter().zip(out.digests);
                for (index, digest) in read {
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

    /// The policy digest of TPM2_PolicyPCR over `pcrs` of the SHA-256 bank at their current
    /// values: what [`Tpm::seal`] binds a secret to.
    pub fn pcr_policy(&mut self, pcrs: &[u32]) -> Result<[u8; 32], TpmError> {
        let selection = selection(HashAlg::Sha256, pcrs)?;
        let values = self.pcr_read_mask(HashAlg::Sha256, selection.mask)?;
        Ok(commands::policy_pcr_digest(selection, &pcr_digest(&values)))
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
        created
    }

    /// Unseals what [`Tpm::seal`] sealed to the current values of `pcrs` (SHA-256 bank), through a
    /// policy session.
    pub fn unseal(
        &mut self,
        sealed: &Sealed,
        pcrs: &[u32],
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let selection = selection(HashAlg::Sha256, pcrs)?;
        let primary = self.storage_key()?;
        let loaded = self
            .execute(&commands::load(primary, &sealed.private, &sealed.public))
            .and_then(|response| commands::parse_handle(&response));
        // A loaded object no longer needs its parent.
        self.flush(primary);
        let object = loaded?;
        let unsealed = self.unseal_object(object, selection);
        self.flush(object);
        unsealed
    }

    fn unseal_object(
        &mut self,
        object: u32,
        selection: PcrSelection,
    ) -> Result<Zeroizing<Vec<u8>>, TpmError> {
        let response = self.execute(&commands::start_policy_session(&nonce()?))?;
        let session = commands::parse_handle(&response)?;
        let mut unseal = || {
            commands::parse_empty(&self.execute(&commands::policy_pcr(session, selection))?)?;
            let response =
                Zeroizing::new(self.execute(&commands::unseal(object, session, &nonce()?))?);
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
        let command = commands::create_primary(commands::RH_OWNER, &commands::srk_template());
        let response = self.execute(&command)?;
        Ok(commands::parse_create_primary(&response)?.handle)
    }

    /// Flushes a transient object or session, logging a failure: the resource manager flushes
    /// whatever is left when the TPM is closed.
    fn flush(&mut self, handle: u32) {
        let flushed = self
            .execute(&commands::flush_context(handle))
            .and_then(|response| commands::parse_empty(&response));
        if let Err(e) = flushed {
            tracing::warn!(
                handle = format_args!("{handle:#x}"),
                "flushing a TPM context: {e}"
            );
        }
    }

    /// The attestation key, created as a primary key of the endorsement hierarchy on first use.
    ///
    /// Primary keys derive from the hierarchy seed and the template, so every boot yields the same
    /// key without persisting anything.
    fn attestation_key(&mut self) -> Result<&AttestationKey, TpmError> {
        let ak = match self.ak.take() {
            Some(ak) => ak,
            None => self.create_attestation_key()?,
        };
        Ok(self.ak.insert(ak))
    }

    fn create_attestation_key(&mut self) -> Result<AttestationKey, TpmError> {
        let command = commands::create_primary(commands::RH_ENDORSEMENT, &commands::ak_template());
        let response = self.execute(&command)?;
        let Primary { handle, public } = commands::parse_create_primary(&response)?;
        let name_alg = commands::ALG_SHA256.to_be_bytes();
        let name = [&name_alg[..], &Sha256::digest(&public)].concat();
        let qualified = Sha256::new()
            .chain_update(commands::RH_ENDORSEMENT.to_be_bytes())
            .chain_update(name);
        let qualified_name = [&name_alg[..], &qualified.finalize()].concat();
        tracing::debug!(
            handle = format_args!("{handle:#x}"),
            "created the attestation key"
        );
        Ok(AttestationKey {
            handle,
            public,
            qualified_name,
        })
    }

    /// Sends a command, re-sending it while the TPM reports itself busy.
    fn execute(&mut self, command: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut attempt = 1;
        loop {
            let response = self.transport.transact(command)?;
            match marshal::response_code(&response).map(ResponseCode) {
                Some(rc) if rc.is_retryable() && attempt < BUSY_ATTEMPTS => {
                    tracing::debug!(%rc, attempt, "tpm busy, retrying");
                    thread::sleep(Duration::from_millis(20) * attempt);
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

/// The selection of `pcrs` in `bank`.
fn selection(bank: HashAlg, pcrs: &[u32]) -> Result<PcrSelection, TpmError> {
    Ok(PcrSelection {
        hash: bank.id(),
        mask: pcr_mask(pcrs)?,
    })
}

/// SHA-256 of the concatenated PCR values: a quote's `pcrDigest`, and what TPM2_PolicyPCR hashes.
fn pcr_digest(values: &[(u32, Vec<u8>)]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (_, value) in values {
        hasher.update(value);
    }
    hasher.finalize().into()
}

/// A session nonce: at least 16 bytes for a SHA-256 session.
fn nonce() -> Result<[u8; 16], TpmError> {
    use rustix::rand::GetRandomFlags;

    let mut nonce = [0; 16];
    let mut filled = 0;
    while filled < nonce.len() {
        filled += rustix::rand::getrandom(&mut nonce[filled..], GetRandomFlags::empty())
            .map_err(io::Error::from)?;
    }
    Ok(nonce)
}

/// The bitmap of `pcrs`, rejecting indices past PCR 23.
fn pcr_mask(pcrs: &[u32]) -> Result<u32, TpmError> {
    let mut mask = 0;
    for &pcr in pcrs {
        if pcr >= PCR_COUNT {
            return Err(TpmError::InvalidPcr(pcr));
        }
        mask |= 1 << pcr;
    }
    Ok(mask)
}

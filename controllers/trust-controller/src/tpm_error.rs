//! Why a TPM operation failed.

use std::io;

use tonic::Status;

use crate::hash_alg::HashAlg;
use crate::response_code::ResponseCode;
use crate::tpm::MAX_NONCE_LEN;

/// A failed TPM operation: refused arguments, the TPM's error, or a response it should not give.
#[derive(Debug, thiserror::Error)]
#[must_use]
pub enum TpmError {
    /// The device could not be written or read.
    #[error("tpm i/o: {0}")]
    Io(#[from] io::Error),
    /// The TPM (or the kernel resource manager) refused the command.
    #[error("tpm returned {0}")]
    Response(ResponseCode),
    /// A response that does not parse, or does not answer the command.
    #[error("malformed tpm response: {0}")]
    Malformed(&'static str),
    /// A PCR index past PCR 23.
    #[error("invalid PCR index {0}, expected 0 to 23")]
    InvalidPcr(u32),
    /// A nonce too long to be qualifying data.
    #[error("nonce of {0} bytes, at most {MAX_NONCE_LEN} are allowed")]
    NonceTooLong(usize),
    /// The bank is not allocated, or the TPM lacks the PCR.
    #[error("PCR {pcr} is not available in the {bank} bank")]
    PcrUnavailable { bank: HashAlg, pcr: u32 },
    /// PCRs were extended at every attempt to read or quote them.
    #[error("PCRs kept changing while being read or quoted")]
    PcrsChanged,
}

impl TpmError {
    /// Whether the TPM refused a sealed object because it is not for this TPM in this state:
    /// sealed by another TPM, or before its owner hierarchy was cleared (it does not load), or to
    /// other PCR values (the policy fails). Asking again cannot succeed.
    #[must_use]
    pub fn is_sealed_elsewhere(&self) -> bool {
        const POLICY_FAIL: u16 = 0x09d;
        const INTEGRITY: u16 = 0x09f;
        const BINDING: u16 = 0x0a5;
        let Self::Response(rc) = self else {
            return false;
        };
        matches!(rc.format_one(), Some(POLICY_FAIL | INTEGRITY | BINDING))
    }
}

/// The status reporting a TPM failure: the client's fault or not.
impl From<TpmError> for Status {
    fn from(error: TpmError) -> Self {
        let message = error.to_string();
        match error {
            TpmError::InvalidPcr(_) | TpmError::NonceTooLong(_) => Self::invalid_argument(message),
            TpmError::PcrUnavailable { .. } => Self::failed_precondition(message),
            TpmError::PcrsChanged => Self::aborted(message),
            TpmError::Io(_) | TpmError::Response(_) | TpmError::Malformed(_) => {
                Self::internal(message)
            }
        }
    }
}

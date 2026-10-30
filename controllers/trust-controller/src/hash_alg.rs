//! The PCR banks, by hash algorithm.

use std::fmt::{self, Display, Formatter};

use crate::commands;

/// A hash algorithm, naming a PCR bank.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
}

impl HashAlg {
    /// TPM_ALG_ID.
    #[must_use]
    pub(crate) fn id(self) -> u16 {
        match self {
            Self::Sha1 => commands::ALG_SHA1,
            Self::Sha256 => commands::ALG_SHA256,
            Self::Sha384 => commands::ALG_SHA384,
        }
    }

    /// The size of its digests, in bytes.
    #[must_use]
    pub(crate) fn digest_len(self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }
}

impl Display for HashAlg {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
        })
    }
}

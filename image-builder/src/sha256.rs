//! SHA-256 digests: source checksums, file hashes, cache keys and the dm-verity root hash.

use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::Digest;

/// A SHA-256 digest, written as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct Sha256([u8; 32]);

#[derive(Debug, thiserror::Error)]
#[error("invalid SHA-256 {0:?}: expected 64 hex digits")]
pub struct InvalidSha256(String);

impl Sha256 {
    pub fn digest(data: impl AsRef<[u8]>) -> Self {
        Self::finalize(sha2::Sha256::new_with_prefix(data))
    }

    pub fn finalize(hasher: sha2::Sha256) -> Self {
        Self(hasher.finalize().into())
    }

    pub fn of_file(path: &Path) -> io::Result<Self> {
        let mut file = std::fs::File::open(path)?;
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0; 1 << 16];
        loop {
            match file.read(&mut buf)? {
                0 => return Ok(Self::finalize(hasher)),
                n => hasher.update(&buf[..n]),
            }
        }
    }

    /// The first `N` bytes (checked at compile time), for identifiers derived from the digest.
    pub fn prefix<const N: usize>(&self) -> [u8; N] {
        const { assert!(N <= 32) };
        std::array::from_fn(|i| self.0[i])
    }

    /// The two 16-byte halves.
    pub fn halves(&self) -> ([u8; 16], [u8; 16]) {
        (self.prefix(), std::array::from_fn(|i| self.0[16 + i]))
    }
}

impl FromStr for Sha256 {
    type Err = InvalidSha256;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        hex::FromHex::from_hex(s)
            .map(Self)
            .map_err(|_| InvalidSha256(s.to_owned()))
    }
}

impl TryFrom<String> for Sha256 {
    type Error = InvalidSha256;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        text.parse()
    }
}

impl From<Sha256> for String {
    fn from(digest: Sha256) -> Self {
        digest.to_string()
    }
}

impl fmt::Display for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl fmt::Debug for Sha256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sha256({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    #[test]
    fn round_trips_hex() {
        let digest: Sha256 = EMPTY.parse().unwrap();
        assert_eq!(digest, Sha256::digest(b""));
        assert_eq!(digest.to_string(), EMPTY);
        assert_eq!(EMPTY.to_uppercase().parse::<Sha256>().unwrap(), digest);
        assert_eq!(
            serde_json::to_value(digest).unwrap(),
            serde_json::json!(EMPTY)
        );
    }

    #[test]
    fn rejects_malformed_digests() {
        for bad in [
            "",
            "abc",
            &EMPTY[..63],
            &format!("{EMPTY}0"),
            &EMPTY.replace('e', "g"),
        ] {
            assert!(bad.parse::<Sha256>().is_err(), "{bad:?} accepted");
        }
    }
}

//! SHA-256 digests: source checksums, file hashes, cache keys and the dm-verity root hash.

use std::fmt;
use std::io::{self, Read};
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use sha2::Digest;

/// A SHA-256 digest, written as 64 lowercase hex digits.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Sha256([u8; 32]);

#[derive(Debug, thiserror::Error)]
#[error("invalid SHA-256 {0:?}: expected 64 hex digits")]
pub struct InvalidSha256(String);

/// A SHA-256 written as a literal, validated at compile time: `sha256!("e3b0…b855")`.
#[macro_export]
macro_rules! sha256 {
    ($hex:literal) => {
        const { $crate::sha256::Sha256::from_hex_const($hex) }
    };
}

impl Sha256 {
    /// Parses 64 hex digits in a const context; panics (a compile error there) otherwise.
    pub const fn from_hex_const(hex: &str) -> Self {
        const fn nibble(c: u8) -> u8 {
            match c {
                b'0'..=b'9' => c - b'0',
                b'a'..=b'f' => c - b'a' + 10,
                b'A'..=b'F' => c - b'A' + 10,
                _ => panic!("invalid SHA-256: non-hex digit"),
            }
        }
        let hex = hex.as_bytes();
        assert!(hex.len() == 64, "invalid SHA-256: expected 64 hex digits");
        let mut bytes = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            bytes[i] = nibble(hex[2 * i]) << 4 | nibble(hex[2 * i + 1]);
            i += 1;
        }
        Self(bytes)
    }

    pub fn digest(data: impl AsRef<[u8]>) -> Self {
        Self::finalize(sha2::Sha256::new_with_prefix(data))
    }

    pub fn finalize(hasher: sha2::Sha256) -> Self {
        Self(hasher.finalize().into())
    }

    pub fn of_reader(mut reader: impl Read) -> io::Result<Self> {
        let mut hasher = sha2::Sha256::new();
        let mut buf = vec![0; 1 << 16];
        loop {
            match reader.read(&mut buf)? {
                0 => return Ok(Self::finalize(hasher)),
                n => hasher.update(&buf[..n]),
            }
        }
    }

    pub fn of_file(path: &Path) -> io::Result<Self> {
        Self::of_reader(std::fs::File::open(path)?)
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

    fn try_from(s: String) -> Result<Self, Self::Error> {
        s.parse()
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
        assert_eq!(serde_json::to_value(digest).unwrap(), serde_json::json!(EMPTY));
    }

    #[test]
    fn rejects_malformed_digests() {
        for bad in ["", "abc", &EMPTY[..63], &format!("{EMPTY}0"), &EMPTY.replace('e', "g")] {
            assert!(bad.parse::<Sha256>().is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn parses_literals_at_compile_time() {
        const DIGEST: Sha256 = Sha256::from_hex_const(EMPTY);
        assert_eq!(DIGEST, Sha256::digest(b""));
        assert_eq!(
            crate::sha256!("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
            DIGEST
        );
    }

    #[test]
    fn splits_into_halves() {
        let digest: Sha256 = format!("{}{}", "11".repeat(16), "22".repeat(16)).parse().unwrap();
        assert_eq!(digest.halves(), ([0x11; 16], [0x22; 16]));
        assert_eq!(digest.prefix::<4>(), [0x11; 4]);
    }
}

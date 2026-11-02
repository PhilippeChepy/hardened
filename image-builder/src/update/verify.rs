//! Checking a new source beyond the checksum the update records: its upstream's OpenPGP
//! signature, against keys pinned in `specs/keys/` (`<name>.asc` or `<name>.gpg`); kernel.org's
//! signed checksum lists; or a checksum the project publishes over HTTPS (PyPI's, go.dev's, a
//! `.sha256` file). What is published but does not match refuses the update; what cannot be
//! checked (no signature, no pinned key) is reported.

use std::fmt;
use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};
use pgp::composed::{CleartextSignedMessage, Deserializable, DetachedSignature, SignedPublicKey};

use crate::sha256::Sha256;
use crate::update::http;
use crate::update::policy::Policy;

/// How a new source was checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verified {
    /// Its detached signature, by a key of `key`.
    Signature { key: String },
    /// A checksum list signed by a key of `key` (kernel.org's `sha256sums.asc`).
    SignedChecksums { key: String },
    /// A checksum the project publishes, over HTTPS.
    PublishedChecksum { by: String },
    /// Not checked, and why.
    Unchecked { why: String },
}

impl fmt::Display for Verified {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature { key } => write!(f, "signature verified ({key})"),
            Self::SignedChecksums { key } => write!(f, "signed checksums verified ({key})"),
            Self::PublishedChecksum { by } => write!(f, "published checksum matches ({by})"),
            Self::Unchecked { why } => write!(f, "UNCHECKED: {why}"),
        }
    }
}

/// A new source to check: downloaded from `url` to `path`, hashing to `sha256`.
pub struct Download<'a> {
    pub url: &'a str,
    pub path: &'a Path,
    pub sha256: Sha256,
    /// The checksum the release index publishes for it, if it does (PyPI, go.dev).
    pub indexed: Option<Sha256>,
}

/// Checks `download` as `policy` and its URL say, with the keys of `keys` (`specs/keys`).
///
/// # Errors
///
/// When a signature or a published checksum does not match, or cannot be read.
pub fn verify(download: &Download, policy: &Policy, keys: &Path) -> anyhow::Result<Verified> {
    let mut notes = Vec::new();
    if let Some((signature, key)) = signature_of(download.url, policy) {
        match keyring(keys, &key)? {
            None => notes.push(format!(
                "no key {}",
                keys.join(format!("{key}.asc")).display()
            )),
            Some(keyring) => match http::bytes(&signature.replace("{url}", download.url)) {
                Ok(signature) => {
                    let content = std::fs::read(download.path)?;
                    check_signature(&signature, &content, &keyring)
                        .with_context(|| format!("{}: its signature", download.url))?;
                    return Ok(Verified::Signature { key });
                }
                Err(e) if http::is_not_found(&e) => notes.push("no signature".to_owned()),
                Err(e) => return Err(e),
            },
        }
    }
    if let Some((list, file)) = kernel_org_checksums(download.url) {
        let key = "kernel.org".to_owned();
        match keyring(keys, &key)? {
            None => notes.push(format!("no key {}", keys.join("kernel.org.asc").display())),
            Some(keyring) => {
                let text = http::text(&list)?;
                let listed = signed_checksum(&text, file, &keyring)
                    .with_context(|| format!("{list}: its signed checksums"))?;
                ensure!(
                    listed == download.sha256,
                    "{}: {list} lists {listed}, the download hashes to {}",
                    download.url,
                    download.sha256
                );
                return Ok(Verified::SignedChecksums { key });
            }
        }
    }
    if let Some(indexed) = download.indexed {
        ensure!(
            indexed == download.sha256,
            "{}: its index lists {indexed}, the download hashes to {}",
            download.url,
            download.sha256
        );
        return Ok(Verified::PublishedChecksum {
            by: "the release index".to_owned(),
        });
    }
    if let Some(checksum) = checksum_of(download.url, policy) {
        let checksum = checksum.replace("{url}", download.url);
        match http::text(&checksum) {
            Ok(text) => {
                let file = download.url.rsplit('/').next().unwrap_or_default();
                let published = published_checksum(&text, file)
                    .with_context(|| format!("{checksum}: no checksum of {file}"))?;
                ensure!(
                    published == download.sha256,
                    "{}: {checksum} has {published}, the download hashes to {}",
                    download.url,
                    download.sha256
                );
                return Ok(Verified::PublishedChecksum { by: checksum });
            }
            Err(e) if http::is_not_found(&e) => notes.push("no checksum file".to_owned()),
            Err(e) => return Err(e),
        }
    }
    if notes.is_empty() {
        notes.push("no signature or checksum known for this source".to_owned());
    }
    Ok(Verified::Unchecked {
        why: notes.join(", "),
    })
}

/// The detached signature of a source and the key checking it: the policy's, else those its
/// host publishes (GNU's `.sig`, Rust's `.asc`).
fn signature_of(url: &str, policy: &Policy) -> Option<(String, String)> {
    let inferred = if url.starts_with("https://ftp.gnu.org/gnu/") {
        Some(("{url}.sig", "gnu-keyring"))
    } else if url.starts_with("https://static.rust-lang.org/dist/") {
        Some(("{url}.asc", "rust"))
    } else {
        None
    };
    let signature = (policy.signature.clone()).or_else(|| inferred.map(|(s, _)| s.to_owned()))?;
    let key = (policy.key.clone()).or_else(|| inferred.map(|(_, k)| k.to_owned()))?;
    Some((signature, key))
}

/// The checksum file of a source: the policy's, else Rust's `.sha256`.
fn checksum_of(url: &str, policy: &Policy) -> Option<String> {
    (policy.checksum.clone()).or_else(|| {
        url.starts_with("https://static.rust-lang.org/dist/")
            .then(|| "{url}.sha256".to_owned())
    })
}

/// kernel.org's signed list of a file's directory, and the file's name.
fn kernel_org_checksums(url: &str) -> Option<(String, &str)> {
    let path = (url.strip_prefix("https://www.kernel.org/pub/"))
        .or_else(|| url.strip_prefix("https://cdn.kernel.org/pub/"))?;
    let (dir, file) = path.rsplit_once('/')?;
    Some((
        format!("https://www.kernel.org/pub/{dir}/sha256sums.asc"),
        file,
    ))
}

/// The keys of `specs/keys/<name>.asc` (or `.gpg`), if pinned.
fn keyring(keys: &Path, name: &str) -> anyhow::Result<Option<Vec<SignedPublicKey>>> {
    let Some(path) = ["asc", "gpg"]
        .iter()
        .map(|extension| keys.join(format!("{name}.{extension}")))
        .find(|path| path.is_file())
    else {
        return Ok(None);
    };
    let file = File::open(&path).with_context(|| path.display().to_string())?;
    let (keys, _) = SignedPublicKey::from_reader_many(BufReader::new(file))
        .with_context(|| format!("{}: not OpenPGP keys", path.display()))?;
    // A keyring of many maintainers (GNU's) may hold keys this OpenPGP does not read (old
    // algorithms): the others still check signatures.
    let keys: Vec<SignedPublicKey> = keys.filter_map(Result::ok).collect();
    ensure!(!keys.is_empty(), "{}: no key read", path.display());
    Ok(Some(keys))
}

/// Checks the detached `signature` (armored or not) of `content` against `keyring`: a primary
/// key or a subkey of one.
fn check_signature(
    signature: &[u8],
    content: &[u8],
    keyring: &[SignedPublicKey],
) -> anyhow::Result<()> {
    let (signature, _) =
        DetachedSignature::from_reader_single(signature).context("not an OpenPGP signature")?;
    let verified = keyring.iter().any(|key| {
        signature.verify(&key.primary_key, content).is_ok()
            || (key.public_subkeys.iter()).any(|sub| signature.verify(&sub.key, content).is_ok())
    });
    ensure!(verified, "{}", unverified(&signature.signature));
    Ok(())
}

/// Why a signature is refused: by a key not pinned (named, to be pinned once trusted), or not
/// matching the content.
fn unverified(signature: &pgp::packet::Signature) -> String {
    let signers: Vec<String> = (signature.issuer_fingerprint().iter())
        .map(|fingerprint| fingerprint.to_string())
        .chain(signature.issuer_key_id().iter().map(|id| id.to_string()))
        .collect();
    format!(
        "no pinned key verifies it (signed by {}): a pinned signer's signature not matching, or \
         a signer to pin once trusted",
        signers.first().map_or("an unnamed key", String::as_str)
    )
}

/// The checksum `text` (a clear-signed `sha256sums.asc`) lists for `file`, once its signature is
/// checked against `keyring`.
fn signed_checksum(text: &str, file: &str, keyring: &[SignedPublicKey]) -> anyhow::Result<Sha256> {
    let (message, _) =
        CleartextSignedMessage::from_string(text).context("not a clear-signed message")?;
    let verified = keyring.iter().any(|key| {
        message.verify(&key.primary_key).is_ok()
            || (key.public_subkeys.iter()).any(|sub| message.verify(&sub.key).is_ok())
    });
    ensure!(verified, "no pinned key made it");
    published_checksum(&message.signed_text(), file).with_context(|| format!("no line for {file}"))
}

/// The checksum of `file` in a checksum file: `<sha256>  <file>` lines (`*` before binary
/// files' names), or a lone checksum.
fn published_checksum(text: &str, file: &str) -> anyhow::Result<Sha256> {
    let mut lone = None;
    for line in text.lines() {
        let mut words = line.split_whitespace();
        let (Some(hash), name) = (words.next(), words.next()) else {
            continue;
        };
        let Ok(sha256) = hash.parse::<Sha256>() else {
            continue;
        };
        match name.map(|name| name.trim_start_matches('*')) {
            Some(name) if name == file || name.ends_with(&format!("/{file}")) => return Ok(sha256),
            Some(_) => {}
            None => lone = Some(sha256),
        }
    }
    match lone {
        Some(sha256) => Ok(sha256),
        None => bail!("no checksum"),
    }
}

/// `specs/keys`.
#[must_use]
pub fn keys_dir(specs: &Path) -> PathBuf {
    specs.join("keys")
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHA: &str = "8839959bfcc7a0f4c609d8e4f53f1c67ae33de23775ec35beb39ff15adf11920";

    #[test]
    fn checksum_files() {
        let sha: Sha256 = SHA.parse().unwrap();
        let list = format!("{SHA}  other.tar.xz\n{SHA} *libtirpc-1.3.8.tar.bz2\n");
        assert_eq!(
            published_checksum(&list, "libtirpc-1.3.8.tar.bz2").unwrap(),
            sha
        );
        assert_eq!(published_checksum(&format!("{SHA}\n"), "x").unwrap(), sha);
        assert!(published_checksum(&format!("{SHA}  other\n"), "x").is_err());
    }

    #[test]
    fn hosts_publishing_signatures() {
        let policy = Policy::default();
        assert_eq!(
            signature_of("https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz", &policy),
            Some(("{url}.sig".to_owned(), "gnu-keyring".to_owned()))
        );
        assert_eq!(signature_of("https://example.org/x.tar.gz", &policy), None);
        assert_eq!(
            kernel_org_checksums(
                "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.58.tar.xz"
            ),
            Some((
                "https://www.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc".to_owned(),
                "linux-6.18.58.tar.xz"
            ))
        );
    }

    #[test]
    fn unchecked_without_anything_published() {
        let dir = tempfile::tempdir().unwrap();
        let download = Download {
            url: "https://example.org/x-1.tar.gz",
            path: dir.path(),
            sha256: SHA.parse().unwrap(),
            indexed: None,
        };
        let verified = verify(&download, &Policy::default(), dir.path()).unwrap();
        assert!(matches!(verified, Verified::Unchecked { .. }), "{verified}");
        let mismatch = Download {
            indexed: Some(Sha256::digest(b"other")),
            ..download
        };
        assert!(verify(&mismatch, &Policy::default(), dir.path()).is_err());
    }

    /// GNU make's signature, by its maintainer's key (and not of a changed file); GNU's keyring
    /// lacks that key: the refusal names it.
    #[test]
    #[ignore = "downloads from ftp.gnu.org and keyserver.ubuntu.com"]
    fn a_gnu_signature() {
        let keys = |url: &str| -> Vec<SignedPublicKey> {
            let keyring = http::bytes(url).unwrap();
            let (keys, _) = SignedPublicKey::from_reader_many(&keyring[..]).unwrap();
            keys.filter_map(Result::ok).collect()
        };
        let maintainer = keys(
            "https://keyserver.ubuntu.com/pks/lookup?op=get&search=0xB2508A90102F8AE3B12A0090DEACCAAEDB78137A",
        );
        let url = "https://ftp.gnu.org/gnu/make/make-4.4.1.tar.gz";
        let content = http::bytes(url).unwrap();
        let signature = http::bytes(&format!("{url}.sig")).unwrap();
        check_signature(&signature, &content, &maintainer).unwrap();
        let mut changed = content.clone();
        changed[100] ^= 1;
        assert!(check_signature(&signature, &changed, &maintainer).is_err());
        let gnu = keys("https://ftp.gnu.org/gnu/gnu-keyring.gpg");
        let error = check_signature(&signature, &content, &gnu).unwrap_err();
        assert!(
            format!("{error}").contains("b2508a90102f8ae3b12a0090deaccaaedb78137a"),
            "{error}"
        );
    }
}

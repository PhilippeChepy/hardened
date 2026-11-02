//! A recipe's `[update]` table: how `cargo builder update` finds and checks its new versions,
//! where what the source's URL implies is not enough. Every key is optional.
//!
//! ```toml
//! [update]
//! track = "6.18"                   # versions of this series only
//! repository = "https://github.com/x/y"   # a git repository whose tags name the versions
//! tag = "release-{version}"        # its tags (`v{version}` by default)
//! listing = "https://example.org/releases.html"   # a page naming the source's files
//! signature = "{url}.asc"          # each new source's detached OpenPGP signature
//! key = "openssl"                  # its signers' keys: specs/keys/openssl.asc
//! checksum = "{url}.sha256"        # or a checksum file the project publishes
//! manual = "follows Kubernetes"    # never updated by the tool, and why
//! ```

use serde::Deserialize;

/// `[update]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
pub struct Policy {
    /// The series new versions must be in (`6.18`: 6.18.x), rather than any newer release.
    pub track: Option<String>,
    /// A git repository whose tags name the versions, rather than the source's own.
    pub repository: Option<String>,
    /// The repository's tags, `{version}` standing for the version.
    pub tag: Option<String>,
    /// A page listing the releases, rather than the source's directory.
    pub listing: Option<String>,
    /// Each new source's detached OpenPGP signature, `{url}` standing for the source's URL.
    pub signature: Option<String>,
    /// The keys the signatures are checked against, `specs/keys/<key>.asc` (or `.gpg`).
    pub key: Option<String>,
    /// A file of checksums, or the checksum alone, the project publishes for each source.
    pub checksum: Option<String>,
    /// Why the recipe is updated by hand only.
    pub manual: Option<String>,
}

//! A pinned source file of a build.

use crate::sha256::Sha256;

/// A pinned source file, recorded (to be fetched, verified and listed in the SBOM) when the
/// build uses it. The source cache names it by its checksum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Source {
    /// Where it is downloaded from.
    pub url: String,
    /// What it must hash to.
    pub sha256: Sha256,
}

impl Source {
    /// An archive, extracted for the build (`.tar.*`, `.tgz`), rather than a file used as is.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        let path = self.url.split(['?', '#']).next().unwrap_or_default();
        path.contains(".tar") || path.ends_with(".tgz")
    }
}

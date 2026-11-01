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
    /// An archive, extracted for the build (`.tar.*`, `.tgz`, or a crates.io `.crate`: a gzipped
    /// tarball), rather than a file used as is.
    #[must_use]
    pub fn is_archive(&self) -> bool {
        let path = self.url.split(['?', '#']).next().unwrap_or_default();
        path.contains(".tar") || path.ends_with(".tgz") || path.ends_with(".crate")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(url: &str) -> Source {
        Source {
            url: url.to_owned(),
            sha256: "eb33e51f49a15e023950cd7825ca74a4a2b43db8354825ac24fc1b7ee09e6fa3"
                .parse()
                .unwrap(),
        }
    }

    #[test]
    fn archives() {
        assert!(source("https://example.org/x-1.0.tar.xz").is_archive());
        assert!(source("https://example.org/x-1.0.tgz?raw").is_archive());
        assert!(source("https://static.crates.io/crates/x/x-1.0%2Bm.crate").is_archive());
        assert!(!source("https://example.org/Cargo.lock").is_archive());
        assert!(!source("https://example.org/cacert.pem").is_archive());
    }
}

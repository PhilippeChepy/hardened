//! A path inside the repository, which a build may read.

use std::path::{Component, Path};

use serde::Deserialize;

/// A path inside the repository: relative, without empty, `.` or `..` components.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(try_from = "String")]
pub struct RepoPath(String);

impl TryFrom<String> for RepoPath {
    type Error = String;

    fn try_from(path: String) -> Result<Self, Self::Error> {
        let normal = !path.is_empty()
            && !path.contains('\0')
            && path.split('/').all(|segment| !segment.is_empty())
            && Path::new(&path)
                .components()
                .all(|c| matches!(c, Component::Normal(_)));
        if normal {
            Ok(Self(path))
        } else {
            Err(format!("invalid repository path {path:?}"))
        }
    }
}

impl RepoPath {
    /// The path, as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<Path> for RepoPath {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_repo_paths() {
        for good in ["Cargo.toml", ".cargo", "serviced/serviced"] {
            assert!(
                RepoPath::try_from(good.to_owned()).is_ok(),
                "{good:?} rejected"
            );
        }
        for bad in ["", "/etc", "../x", "a/../b", "./a", "a//b", "serviced/"] {
            assert!(
                RepoPath::try_from(bad.to_owned()).is_err(),
                "{bad:?} accepted"
            );
        }
    }
}

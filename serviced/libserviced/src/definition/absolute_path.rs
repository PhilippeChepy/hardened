//! A path that names the same file whatever the working directory.

use std::fmt::{self, Display, Formatter};
use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::definition::Error;

/// An absolute path without NUL bytes, so that system calls take it as is; UTF-8, like the
/// service files it comes from.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct AbsolutePath(String);

impl AbsolutePath {
    /// The path.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.0)
    }

    /// The path, as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for AbsolutePath {
    type Error = Error;

    fn try_from(path: String) -> Result<Self, Error> {
        if path.starts_with('/') && !path.contains('\0') {
            Ok(Self(path))
        } else {
            Err(not_absolute(Path::new(&path)))
        }
    }
}

impl TryFrom<PathBuf> for AbsolutePath {
    type Error = Error;

    fn try_from(path: PathBuf) -> Result<Self, Error> {
        let path = path
            .into_os_string()
            .into_string()
            .map_err(|path| not_absolute(Path::new(&path)))?;
        Self::try_from(path)
    }
}

fn not_absolute(path: &Path) -> Error {
    Error::Invalid(format!(
        "{} is not an absolute path without NUL bytes",
        path.display()
    ))
}

impl FromStr for AbsolutePath {
    type Err = Error;

    fn from_str(path: &str) -> Result<Self, Error> {
        Self::try_from(path.to_owned())
    }
}

impl From<AbsolutePath> for String {
    fn from(path: AbsolutePath) -> Self {
        path.0
    }
}

impl From<AbsolutePath> for PathBuf {
    fn from(path: AbsolutePath) -> Self {
        path.0.into()
    }
}

impl Deref for AbsolutePath {
    type Target = Path;

    fn deref(&self) -> &Path {
        self.as_path()
    }
}

impl AsRef<Path> for AbsolutePath {
    fn as_ref(&self) -> &Path {
        self.as_path()
    }
}

impl Display for AbsolutePath {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let path: AbsolutePath = "/run/a".parse().unwrap();
        assert_eq!(path.as_path(), Path::new("/run/a"));
        for bad in ["", "run/a", "./a", "/run/a\0b"] {
            assert!(bad.parse::<AbsolutePath>().is_err(), "{bad:?} accepted");
        }
    }
}

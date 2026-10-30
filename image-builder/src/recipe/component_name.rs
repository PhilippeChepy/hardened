//! The name of a component (and of a target).

use std::borrow::{Borrow, Cow};
use std::fmt::{self, Display, Formatter};
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// A component name: lowercase ASCII letters, digits and inner `-`. Used in output paths and
/// container mount points, so it can never contain `/` or `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(into = "String", try_from = "String")]
pub struct ComponentName(Cow<'static, str>);

/// A name that is not a [`ComponentName`].
#[derive(Debug, thiserror::Error)]
#[error("invalid component name {0:?}: use lowercase ASCII letters, digits and '-'")]
pub struct InvalidComponentName(String);

/// A component name literal, validated at compile time: `name!("kernel")`.
#[macro_export]
macro_rules! name {
    ($name:literal) => {
        const { $crate::recipe::ComponentName::from_static($name) }
    };
}

impl ComponentName {
    const fn is_valid(name: &[u8]) -> bool {
        if name.is_empty() || name[0] == b'-' || name[name.len() - 1] == b'-' {
            return false;
        }
        let mut i = 0;
        while i < name.len() {
            let b = name[i];
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return false;
            }
            i += 1;
        }
        true
    }

    /// For literals (see [`name!`](crate::name!)).
    ///
    /// # Panics
    ///
    /// On an invalid name: a compile error in a const context.
    #[must_use]
    pub const fn from_static(name: &'static str) -> Self {
        assert!(Self::is_valid(name.as_bytes()), "invalid component name");
        Self(Cow::Borrowed(name))
    }

    /// The name, as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ComponentName {
    type Err = InvalidComponentName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        name.to_owned().try_into()
    }
}

impl TryFrom<String> for ComponentName {
    type Error = InvalidComponentName;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        if Self::is_valid(name.as_bytes()) {
            Ok(Self(Cow::Owned(name)))
        } else {
            Err(InvalidComponentName(name))
        }
    }
}

impl From<ComponentName> for String {
    fn from(name: ComponentName) -> Self {
        name.0.into_owned()
    }
}

impl Borrow<str> for ComponentName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<Path> for ComponentName {
    fn as_ref(&self) -> &Path {
        self.as_str().as_ref()
    }
}

impl Display for ComponentName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_names() {
        for bad in ["Runc", "run_c", "-runc", "runc-", "", "../runc", "a/b"] {
            assert!(bad.parse::<ComponentName>().is_err(), "{bad:?} accepted");
        }
        assert_eq!(name!("llvm-runtimes").as_str(), "llvm-runtimes");
        assert_eq!(
            "llvm-runtimes".parse::<ComponentName>().unwrap(),
            name!("llvm-runtimes")
        );
    }
}

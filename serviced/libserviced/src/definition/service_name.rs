//! The name of a service, which is also its file's name.

use std::borrow::{Borrow, Cow};
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::definition::Error;

/// A service's name: 1 to 128 lowercase alphanumerics, `-`, `_` and `.`, starting with an
/// alphanumeric.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(Cow<'static, str>);

impl ServiceName {
    /// The name, as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether `name` is a valid service name.
    #[must_use]
    pub const fn is_valid(name: &str) -> bool {
        let bytes = name.as_bytes();
        let Some(&first) = bytes.first() else {
            return false;
        };
        if bytes.len() > 128 || !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
            return false;
        }
        let mut i = 0;
        while i < bytes.len() {
            let c = bytes[i];
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, b'-' | b'_' | b'.')) {
                return false;
            }
            i += 1;
        }
        true
    }

    /// The name `name`, for a `const` item: checked when compiling, an invalid name fails the
    /// build (`const CONTAINERD: ServiceName = ServiceName::from_static("containerd");`).
    #[must_use]
    pub const fn from_static(name: &'static str) -> Self {
        assert!(Self::is_valid(name), "invalid service name");
        Self(Cow::Borrowed(name))
    }
}

impl TryFrom<String> for ServiceName {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Error> {
        if Self::is_valid(&name) {
            Ok(Self(Cow::Owned(name)))
        } else {
            Err(Error::Invalid(format!("invalid service name {name:?}")))
        }
    }
}

impl FromStr for ServiceName {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        Self::try_from(name.to_owned())
    }
}

impl From<ServiceName> for String {
    fn from(name: ServiceName) -> Self {
        name.0.into_owned()
    }
}

impl Display for ServiceName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Borrow<str> for ServiceName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constants_equal_parsed_names() {
        const CONSOLE: ServiceName = ServiceName::from_static("workload-console");
        assert_eq!(CONSOLE, "workload-console".parse::<ServiceName>().unwrap());
        assert_eq!(String::from(CONSOLE), "workload-console");
    }

    #[test]
    fn names() {
        for good in ["containerd", "network-controller", "workload-web.1", "a_b"] {
            assert!(good.parse::<ServiceName>().is_ok(), "{good} rejected");
        }
        for bad in ["", "-x", "Upper", "a/b", "a b", ".hidden"] {
            assert!(bad.parse::<ServiceName>().is_err(), "{bad} accepted");
        }
    }
}

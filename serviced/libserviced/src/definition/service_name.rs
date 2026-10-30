//! The name of a service, which is also its file's name.

use std::borrow::Borrow;
use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::definition::Error;

/// A service's name: 1 to 128 lowercase alphanumerics, `-`, `_` and `.`, starting with an
/// alphanumeric.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ServiceName(String);

impl ServiceName {
    /// The name, as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ServiceName {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Error> {
        let valid = (1..=128).contains(&name.len())
            && name.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
            && name.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '-' | '_' | '.')
            });
        if valid {
            Ok(Self(name))
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
        name.0
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
    fn names() {
        for good in ["containerd", "network-controller", "workload-web.1", "a_b"] {
            assert!(good.parse::<ServiceName>().is_ok(), "{good} rejected");
        }
        for bad in ["", "-x", "Upper", "a/b", "a b", ".hidden"] {
            assert!(bad.parse::<ServiceName>().is_err(), "{bad} accepted");
        }
    }
}

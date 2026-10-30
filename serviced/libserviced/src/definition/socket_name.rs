//! The name of a service's socket.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::definition::Error;

/// Prefix of the variable listing the services allowed on a socket.
const ALLOW_PREFIX: &str = "SERVICED_ALLOW_";

/// A socket's name: lowercase alphanumerics and `-`, at least one. Valid as is in
/// `LISTEN_FDNAMES` (`:`-separated), and distinct names make distinct
/// [`allow_variable`](Self::allow_variable)s.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct SocketName(String);

impl SocketName {
    /// The name, as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The variable listing the services allowed on the socket: `SERVICED_ALLOW_` and the name
    /// upper-cased, `-` as `_`.
    #[must_use]
    pub fn allow_variable(&self) -> String {
        format!(
            "{ALLOW_PREFIX}{}",
            self.0.to_ascii_uppercase().replace('-', "_")
        )
    }
}

impl TryFrom<String> for SocketName {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Error> {
        let valid = !name.is_empty()
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid {
            Ok(Self(name))
        } else {
            Err(Error::Invalid(format!("invalid socket name {name:?}")))
        }
    }
}

impl FromStr for SocketName {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        Self::try_from(name.to_owned())
    }
}

impl From<SocketName> for String {
    fn from(name: SocketName) -> Self {
        name.0
    }
}

impl Display for SocketName {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names() {
        let name: SocketName = "machine-admin2".parse().unwrap();
        assert_eq!(name.allow_variable(), "SERVICED_ALLOW_MACHINE_ADMIN2");
        for bad in ["", "Api", "a_b", "a:b", "a,b", "a b", "a=b"] {
            assert!(bad.parse::<SocketName>().is_err(), "{bad:?} accepted");
        }
    }
}

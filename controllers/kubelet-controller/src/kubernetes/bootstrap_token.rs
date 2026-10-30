//! kubelet's TLS bootstrap token.

use std::fmt;

use controllers_helpers::{InvalidValue, PrivateKey};
use serde::{Deserialize, Serialize};

/// A bootstrap token, `<id>.<secret>` (6 and 16 lowercase alphanumerics). Like [`PrivateKey`],
/// never displayed or logged, but serialized as itself.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BootstrapToken(String);

impl BootstrapToken {
    /// The token, to write kubelet's bootstrap kubeconfig. The only way to read it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BootstrapToken {
    type Error = InvalidValue;

    fn try_from(token: String) -> Result<Self, Self::Error> {
        let part = |text: &str, len| {
            text.len() == len
                && text
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        };
        match token.split_once('.') {
            Some((id, secret)) if part(id, 6) && part(secret, 16) => Ok(Self(token)),
            _ => Err(InvalidValue::new(
                "bootstrap token",
                PrivateKey::REDACTED,
                "must be <6 lowercase alphanumerics>.<16 lowercase alphanumerics>",
            )),
        }
    }
}

impl From<BootstrapToken> for String {
    fn from(token: BootstrapToken) -> Self {
        token.0
    }
}

impl fmt::Debug for BootstrapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PrivateKey::REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_tokens_are_never_shown_but_serialize_back() {
        let token = BootstrapToken::try_from("abcdef.0123456789abcdef".to_owned()).unwrap();
        assert_eq!(token.expose(), "abcdef.0123456789abcdef");
        assert_eq!(format!("{token:?}"), PrivateKey::REDACTED);
        assert_eq!(
            serde_json::to_string(&token).unwrap(),
            "\"abcdef.0123456789abcdef\""
        );
        for bad in [
            "abcdef",
            "abcde.0123456789abcdef",
            "ABCDEF.0123456789abcdef",
            "abcdef.0123456789abcdeF",
        ] {
            let error = BootstrapToken::try_from(bad.to_owned()).unwrap_err();
            assert!(
                !error.to_string().contains("0123"),
                "the token is not echoed"
            );
        }
    }
}

//! Why a value was rejected.

/// Why a value was rejected.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} {value:?}: {reason}")]
pub struct InvalidValue {
    kind: &'static str,
    value: String,
    reason: &'static str,
}

impl InvalidValue {
    /// The longest prefix of a rejected value an error shows: huge inputs stay out of messages.
    const MAX_SHOWN_LEN: usize = 128;

    /// `value` is not a valid `kind` (what was expected, e.g. `"hostname"`) because of `reason`.
    pub fn new(kind: &'static str, value: &str, reason: &'static str) -> Self {
        let value = if value.len() > Self::MAX_SHOWN_LEN {
            format!(
                "{}…",
                &value[..value.floor_char_boundary(Self::MAX_SHOWN_LEN)]
            )
        } else {
            value.to_owned()
        };
        Self {
            kind,
            value,
            reason,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_values_are_truncated() {
        let error = InvalidValue::new("hostname", &"é".repeat(100), "is too long");
        assert!(
            error
                .to_string()
                .contains(&format!("\"{}…\"", "é".repeat(64))),
            "{error}"
        );
    }
}

//! Why a protobuf message was rejected.

use std::fmt;

/// Why a protobuf message does not convert into domain values: the field at fault (a path such
/// as `tls.certificate` or `node_taints[2].key`, empty when the message as a whole is at fault)
/// and why. Controllers answer `INVALID_ARGUMENT` with it.
#[must_use]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub struct InvalidMessage {
    field: String,
    reason: String,
}

impl InvalidMessage {
    /// `field` is invalid because of `reason`.
    pub fn new(field: impl Into<String>, reason: impl fmt::Display) -> Self {
        Self {
            field: field.into(),
            reason: reason.to_string(),
        }
    }

    /// The message as a whole is invalid, because of `reason`.
    pub fn whole(reason: impl fmt::Display) -> Self {
        Self::new(String::new(), reason)
    }

    /// The path of the field at fault, empty when the message as a whole is.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The same error, seen from the message holding this one in `parent`.
    pub fn within(mut self, parent: &str) -> Self {
        self.field = if self.field.is_empty() {
            parent.to_owned()
        } else {
            format!("{parent}.{}", self.field)
        };
        self
    }
}

impl fmt::Display for InvalidMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.field.is_empty() {
            f.write_str(&self.reason)
        } else {
            write!(f, "{}: {}", self.field, self.reason)
        }
    }
}

/// Names the field a conversion of a message's value was for.
pub trait FieldResult<T> {
    /// The error, if any, as one of the field `name`.
    fn field(self, name: &str) -> Result<T, InvalidMessage>;
}

impl<T, E: fmt::Display> FieldResult<T> for Result<T, E> {
    fn field(self, name: &str) -> Result<T, InvalidMessage> {
        self.map_err(|error| InvalidMessage::new(name, error))
    }
}

/// Places the errors of a nested message's conversion in the message holding it.
pub trait WithinResult<T> {
    /// The error, if any, as one of the field `parent`'s.
    fn within(self, parent: &str) -> Result<T, InvalidMessage>;
}

impl<T> WithinResult<T> for Result<T, InvalidMessage> {
    fn within(self, parent: &str) -> Result<T, InvalidMessage> {
        self.map_err(|error| error.within(parent))
    }
}

/// The value of a message field proto3 cannot make required.
pub fn required<T>(value: Option<T>, field: &str) -> Result<T, InvalidMessage> {
    value.ok_or_else(|| InvalidMessage::new(field, "is required"))
}

/// Each of `values` converted, an error naming the index of the first one that does not.
pub fn convert_each<T, U, E>(
    values: impl IntoIterator<Item = T>,
    field: &str,
    convert: impl Fn(T) -> Result<U, E>,
) -> Result<Vec<U>, InvalidMessage>
where
    E: fmt::Display,
{
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| convert(value).field(&format!("{field}[{index}]")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors_name_the_field_path() {
        let error = InvalidMessage::new("key", "is empty").within("node_taints[2]");
        assert_eq!(error.field(), "node_taints[2].key");
        assert_eq!(error.to_string(), "node_taints[2].key: is empty");
        let whole = InvalidMessage::whole("low must be below high");
        assert_eq!(whole.to_string(), "low must be below high");
        assert_eq!(
            whole.within("threshold_percent").to_string(),
            "threshold_percent: low must be below high"
        );
    }
}

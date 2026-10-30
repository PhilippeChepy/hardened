//! Lists of at least one value.

use std::slice;
use std::vec;

use serde::{Deserialize, Serialize};

/// At least one value, in order. A list a setting cannot do without (time servers, mirror
/// endpoints): an empty one is rejected where it is parsed, not where it is used. Serialized as a
/// list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<T>")]
pub struct NonEmpty<T>(Vec<T>);

impl<T> NonEmpty<T> {
    /// The list of `first` alone.
    #[must_use]
    pub fn new(first: T) -> Self {
        Self(vec![first])
    }

    /// `values`, unless there are none.
    #[must_use]
    pub fn from_vec(values: Vec<T>) -> Option<Self> {
        (!values.is_empty()).then_some(Self(values))
    }

    /// The first value.
    #[must_use]
    pub fn first(&self) -> &T {
        &self.0[0]
    }

    /// The values, in order.
    pub fn iter(&self) -> slice::Iter<'_, T> {
        self.0.iter()
    }
}

impl<T> IntoIterator for NonEmpty<T> {
    type Item = T;
    type IntoIter = vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a NonEmpty<T> {
    type Item = &'a T;
    type IntoIter = slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl<T> TryFrom<Vec<T>> for NonEmpty<T> {
    type Error = &'static str;

    fn try_from(values: Vec<T>) -> Result<Self, Self::Error> {
        Self::from_vec(values).ok_or("an empty list, where at least one value is needed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deserialization_rejects_an_empty_list() {
        let values: NonEmpty<u8> = serde_json::from_str("[1, 2]").unwrap();
        assert_eq!(values.first(), &1);
        assert!(values.iter().eq(&[1, 2]));
        assert_eq!(serde_json::to_string(&values).unwrap(), "[1,2]");
        assert!(serde_json::from_str::<NonEmpty<u8>>("[]").is_err());
        assert_eq!(NonEmpty::<u8>::from_vec(Vec::new()), None);
    }
}

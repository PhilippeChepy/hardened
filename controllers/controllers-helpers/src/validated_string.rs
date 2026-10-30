//! The `validated_string!` macro, which defines most string newtypes of the settings.

/// Defines a string newtype holding only the values `$check` accepts (a
/// `fn(&str) -> Result<(), &'static str>`, the error being the reason), with its conversions
/// from and to `String`. Users depend on `serde`, which the newtype derives.
#[macro_export]
macro_rules! validated_string {
    ($(#[$meta:meta])* $name:ident, $kind:literal, $check:expr) => {
        $(#[$meta])*
        #[derive(
            Debug,
            Clone,
            PartialEq,
            Eq,
            PartialOrd,
            Ord,
            Hash,
            ::serde::Serialize,
            ::serde::Deserialize,
        )]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// The validated text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::InvalidValue;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let check: fn(&str) -> Result<(), &'static str> = $check;
                match check(&value) {
                    Ok(()) => Ok(Self(value)),
                    Err(reason) => Err($crate::InvalidValue::new($kind, &value, reason)),
                }
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::InvalidValue;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        // Sound: equality, ordering and hashing are those of the inner string.
        impl ::std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

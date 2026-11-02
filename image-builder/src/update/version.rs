//! Release versions as recipes write them: numbers separated by `.`, `-` or `_` (`6.18.58`,
//! `2026-10-20`, `1_0_8`), after a fixed word some projects put first (`stable202608`). Anything
//! else after the first digit (`-rc1`, `b2`, `.dev0`) is a pre-release, never taken.

use std::cmp::Ordering;
use std::fmt;

/// A release version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    text: String,
    prefix: String,
    numbers: Vec<u64>,
}

impl Version {
    /// `text` as a release version, if it is one.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        let digits = text.find(|c: char| c.is_ascii_digit())?;
        let (prefix, rest) = text.split_at(digits);
        if !prefix.chars().all(|c| c.is_ascii_alphabetic()) {
            return None;
        }
        let numbers = rest
            .split(['.', '-', '_'])
            .map(|number| {
                let all_digits = !number.is_empty() && number.bytes().all(|b| b.is_ascii_digit());
                all_digits.then(|| number.parse().ok()).flatten()
            })
            .collect::<Option<Vec<u64>>>()?;
        Some(Self {
            text: text.to_owned(),
            prefix: prefix.to_owned(),
            numbers,
        })
    }

    /// Whether `self` is a release of the same scheme as `other` (the same leading word), so that
    /// they compare.
    #[must_use]
    pub fn same_scheme(&self, other: &Self) -> bool {
        self.prefix == other.prefix
    }

    /// Whether it is in the series `track` (`6.18`: 6.18 and 6.18.x; `595`: 595.x).
    #[must_use]
    pub fn in_track(&self, track: &Self) -> bool {
        self.same_scheme(track) && self.numbers.starts_with(&track.numbers)
    }

    /// As written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        (self.prefix.cmp(&other.prefix))
            .then_with(|| self.numbers.cmp(&other.numbers))
            .then_with(|| self.text.cmp(&other.text))
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(text: &str) -> Version {
        Version::parse(text).unwrap()
    }

    #[test]
    fn releases_only() {
        for release in [
            "6.18.58",
            "2026-10-20",
            "1_0_8",
            "stable202608",
            "595.112.07",
        ] {
            assert!(Version::parse(release).is_some(), "{release}");
        }
        for other in ["6.19-rc1", "3.14.0b2", "1.0.dev0", "v", "", "1..2", "x-1.0"] {
            assert!(Version::parse(other).is_none(), "{other}");
        }
    }

    #[test]
    fn numeric_order() {
        assert!(v("6.18.100") > v("6.18.58"));
        assert!(v("1.10") > v("1.9"));
        assert!(v("2026-10-20") > v("2026-09-30"));
        assert!(v("595.112.07") > v("595.112.6"));
        assert!(v("1.2.1") > v("1.2"));
    }

    #[test]
    fn tracks() {
        assert!(v("6.18.60").in_track(&v("6.18")));
        assert!(v("6.18").in_track(&v("6.18")));
        assert!(!v("6.180.1").in_track(&v("6.18")));
        assert!(!v("6.19.1").in_track(&v("6.18")));
        assert!(!v("6.18.1").same_scheme(&v("stable202611")));
    }
}

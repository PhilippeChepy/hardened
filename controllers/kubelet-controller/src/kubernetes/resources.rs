//! Resource reservations, eviction thresholds and durations, in kubelet's value formats.

use std::fmt;

use controllers_helpers::{InvalidValue, validated_string};
use serde::{Deserialize, Serialize};

/// A resource kubelet reserves for the system or for Kubernetes daemons (`kubeReserved`,
/// `systemReserved`).
#[allow(missing_docs, reason = "self-explanatory variants")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservedResource {
    Cpu,
    Memory,
    EphemeralStorage,
    Pid,
}

/// An eviction signal (`evictionHard` keys).
#[allow(missing_docs, reason = "kubelet's signals, self-explanatory")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum EvictionSignal {
    #[serde(rename = "memory.available")]
    MemoryAvailable,
    #[serde(rename = "nodefs.available")]
    NodefsAvailable,
    #[serde(rename = "nodefs.inodesFree")]
    NodefsInodesFree,
    #[serde(rename = "imagefs.available")]
    ImagefsAvailable,
    #[serde(rename = "imagefs.inodesFree")]
    ImagefsInodesFree,
    #[serde(rename = "pid.available")]
    PidAvailable,
}

impl EvictionSignal {
    /// kubelet's name of the signal.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MemoryAvailable => "memory.available",
            Self::NodefsAvailable => "nodefs.available",
            Self::NodefsInodesFree => "nodefs.inodesFree",
            Self::ImagefsAvailable => "imagefs.available",
            Self::ImagefsInodesFree => "imagefs.inodesFree",
            Self::PidAvailable => "pid.available",
        }
    }
}

validated_string!(
    /// A Kubernetes quantity (`100m`, `1.5Gi`, `129e6`), unsigned: a reservation or a threshold
    /// is never negative.
    Quantity,
    "Kubernetes quantity",
    check_quantity
);

fn check_quantity(text: &str) -> Result<(), &'static str> {
    if is_quantity(text) {
        Ok(())
    } else {
        Err("must be a number with an optional suffix (m, k, M, Mi, Gi, e6...)")
    }
}

/// An eviction threshold: a quantity, or a percentage from 0 (included) to 100 (excluded), whose
/// value it keeps from its parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Threshold {
    text: String,
    /// The percentage's bits (`f64::to_bits`), for a percentage.
    percent: Option<u64>,
}

impl Threshold {
    /// The threshold, as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The percentage, for a percentage.
    #[must_use]
    pub fn percent(&self) -> Option<f64> {
        self.percent.map(f64::from_bits)
    }
}

impl TryFrom<String> for Threshold {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let invalid = |reason| InvalidValue::new("eviction threshold", &text, reason);
        check_threshold(&text).map_err(invalid)?;
        let percent = match text.strip_suffix('%') {
            Some(percent) => Some(
                percent
                    .parse::<f64>()
                    .map_err(|_| invalid("a percentage must be a number"))?
                    .to_bits(),
            ),
            None => None,
        };
        Ok(Self { text, percent })
    }
}

impl std::str::FromStr for Threshold {
    type Err = InvalidValue;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        Self::try_from(text.to_owned())
    }
}

impl From<Threshold> for String {
    fn from(threshold: Threshold) -> Self {
        threshold.text
    }
}

impl fmt::Display for Threshold {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn check_threshold(text: &str) -> Result<(), &'static str> {
    match text.strip_suffix('%') {
        Some(percent) => match percent.parse::<f64>() {
            Ok(value) if is_number(percent) && (0.0..100.0).contains(&value) => Ok(()),
            _ => Err("a percentage must be from 0 to 100 (excluded)"),
        },
        None if is_quantity(text) => Ok(()),
        None => Err("must be a quantity or a percentage"),
    }
}

/// `<digits>[.<digits>]`, either part possibly empty but not both.
#[must_use]
fn is_number(text: &str) -> bool {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    !(whole.is_empty() && fraction.is_empty()) && digits(whole) && digits(fraction)
}

/// Kubernetes' quantity grammar (`k8s.io/apimachinery/pkg/api/resource`), without a sign.
#[must_use]
fn is_quantity(text: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        "Ki", "Mi", "Gi", "Ti", "Pi", "Ei", "n", "u", "m", "k", "M", "G", "T", "P", "E", "",
    ];
    let end = text
        .find(|c: char| !c.is_ascii_digit() && c != '.')
        .unwrap_or(text.len());
    let (number, suffix) = text.split_at(end);
    if !is_number(number) {
        return false;
    }
    if let Some(exponent) = suffix.strip_prefix(['e', 'E'])
        && !exponent.is_empty()
    {
        let exponent = exponent.strip_prefix(['+', '-']).unwrap_or(exponent);
        return !exponent.is_empty() && exponent.chars().all(|c| c.is_ascii_digit());
    }
    SUFFIXES.contains(&suffix)
}

/// A duration in Go's format, as kubelet's configuration takes it, restricted (like Bottlerocket)
/// to hours, minutes, seconds and milliseconds, in that order: `1h30m`, `90s`, `1.5h`. Kept as
/// milliseconds, and written in its normalized form ([`fmt::Display`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Duration(u64);

impl Duration {
    /// The duration of `millis` milliseconds.
    #[must_use]
    pub(crate) fn from_millis(millis: u64) -> Self {
        Self(millis)
    }

    /// The duration in milliseconds.
    #[must_use]
    pub(crate) fn millis(self) -> u64 {
        self.0
    }

    /// The milliseconds of `text`; `None` when it is not a duration.
    #[must_use]
    fn parse_millis(text: &str) -> Option<u64> {
        // In the order they must come in.
        const UNITS: &[(&str, f64)] = &[
            ("h", 3_600_000.0),
            ("m", 60_000.0),
            ("s", 1000.0),
            ("ms", 1.0),
        ];
        let mut rest = text;
        let mut next_unit: usize = 0;
        let mut millis: f64 = 0.0;
        while !rest.is_empty() {
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
            let (number, tail) = rest.split_at(end);
            if !is_number(number) || number.starts_with('.') || number.ends_with('.') {
                return None;
            }
            // The last match: `ms` rather than `m`.
            let rank = UNITS.iter().rposition(|(unit, _)| tail.starts_with(unit))?;
            let (unit, factor) = UNITS[rank];
            if rank < next_unit {
                return None;
            }
            next_unit = rank + 1;
            millis += number.parse::<f64>().ok()? * factor;
            rest = &tail[unit.len()..];
        }
        (!text.is_empty()).then_some(millis as u64)
    }
}

impl TryFrom<String> for Duration {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        Self::parse_millis(&text).map(Self).ok_or_else(|| {
            InvalidValue::new(
                "duration",
                &text,
                "must be hours, minutes, seconds and milliseconds, in that order \
                 (1h30m, 90s, 500ms)",
            )
        })
    }
}

impl From<Duration> for String {
    fn from(duration: Duration) -> Self {
        duration.to_string()
    }
}

/// Hours, minutes, seconds and milliseconds, the zero ones left out (`1h30m`, `1m0s5ms` written
/// `1m5ms`), and `0s` for zero. Go's `time.ParseDuration`, hence kubelet, reads it.
impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const UNITS: &[(&str, u64)] = &[("h", 3_600_000), ("m", 60_000), ("s", 1000), ("ms", 1)];
        if self.0 == 0 {
            return f.write_str("0s");
        }
        let mut rest = self.0;
        for (unit, factor) in UNITS {
            let count = rest / factor;
            rest %= factor;
            if count > 0 {
                write!(f, "{count}{unit}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quantities() {
        for good in [
            "100", "100m", "1.5Gi", "0.5", ".5", "1.", "129e6", "1E3", "1e-3", "10Mi", "1000n",
            "2k",
        ] {
            assert!(good.parse::<Quantity>().is_ok(), "{good}");
        }
        for bad in [
            "", "-1", "+1", "1KB", "12ki", "1e", "e3", "1 Gi", "1Gi ", "Gi", ".", "10%",
        ] {
            assert!(bad.parse::<Quantity>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn thresholds() {
        for good in ["15%", "0%", "99.5%", "100Mi", "10"] {
            assert!(good.parse::<Threshold>().is_ok(), "{good}");
        }
        for bad in ["100%", "-1%", "x%", "%", "1e2%", ""] {
            assert!(bad.parse::<Threshold>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn durations() {
        for (text, millis) in [
            ("2m", 120_000),
            ("1h30m", 5_400_000),
            ("1.5h", 5_400_000),
            ("500ms", 500),
            ("1m2s3ms", 62_003),
        ] {
            assert_eq!(
                Duration::try_from(text.to_owned()).unwrap().millis(),
                millis,
                "{text}"
            );
        }
        for bad in [
            "", "100", "1m2h", "1h1h", "1.s", ".5s", "1d", "1 h", "9ns", "1ms2s",
        ] {
            assert!(Duration::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn normalized_durations() {
        for (millis, text) in [
            (0, "0s"),
            (500, "500ms"),
            (120_000, "2m"),
            (5_400_000, "1h30m"),
            (90_061_001, "25h1m1s1ms"),
        ] {
            let duration = Duration::from_millis(millis);
            assert_eq!(duration.to_string(), text);
            assert_eq!(
                Duration::try_from(text.to_owned()).unwrap(),
                duration,
                "parses back"
            );
        }
    }
}

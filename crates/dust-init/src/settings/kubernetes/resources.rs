//! Resource reservations, eviction thresholds and image garbage collection: Bottlerocket's keys
//! and value formats (`bottlerocket-settings-models`, `modeled-types/src/kubernetes.rs`).

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::{InvalidValue, validated_string};

/// A resource kubelet reserves for the system or for Kubernetes daemons (`kubeReserved`,
/// `systemReserved`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ReservedResource {
    Cpu,
    Memory,
    EphemeralStorage,
    Pid,
}

impl ReservedResource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Memory => "memory",
            Self::EphemeralStorage => "ephemeral-storage",
            Self::Pid => "pid",
        }
    }
}

/// An eviction signal (`evictionHard` keys).
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
    |text| if is_quantity(text) { Ok(()) } else { Err("must be a number with an optional suffix (m, k, M, Mi, Gi, e6...)") }
);

validated_string!(
    /// An eviction threshold: a quantity, or a percentage from 0 (included) to 100 (excluded).
    Threshold,
    "eviction threshold",
    |text| match text.strip_suffix('%') {
        Some(percent) => match percent.parse::<f64>() {
            Ok(value) if is_number(percent) && (0.0..100.0).contains(&value) => Ok(()),
            _ => Err("a percentage must be from 0 to 100 (excluded)"),
        },
        None if is_quantity(text) => Ok(()),
        None => Err("must be a quantity or a percentage"),
    }
);

/// `<digits>[.<digits>]`, either part possibly empty but not both.
fn is_number(text: &str) -> bool {
    let (whole, fraction) = text.split_once('.').unwrap_or((text, ""));
    let digits = |s: &str| s.chars().all(|c| c.is_ascii_digit());
    !(whole.is_empty() && fraction.is_empty()) && digits(whole) && digits(fraction)
}

/// Kubernetes' quantity grammar (`k8s.io/apimachinery/pkg/api/resource`), without a sign.
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

/// A whole percentage, 0 to 100, written as a number or a string (as Bottlerocket accepts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "NumberOrString", into = "u8")]
pub struct Percent(u8);

impl Percent {
    pub fn get(self) -> u8 {
        self.0
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum NumberOrString {
    Number(i64),
    String(String),
}

impl TryFrom<NumberOrString> for Percent {
    type Error = InvalidValue;

    fn try_from(value: NumberOrString) -> Result<Self, Self::Error> {
        let text = match value {
            NumberOrString::Number(n) => n.to_string(),
            NumberOrString::String(s) => s,
        };
        match text.parse::<u8>() {
            Ok(n) if n <= 100 => Ok(Self(n)),
            _ => Err(InvalidValue::new(
                "percentage",
                &text,
                "must be a whole number from 0 to 100",
            )),
        }
    }
}

impl From<Percent> for u8 {
    fn from(percent: Percent) -> Self {
        percent.0
    }
}

/// A duration in Go's format, as kubelet's configuration takes it, restricted (like Bottlerocket)
/// to hours, minutes, seconds and milliseconds, in that order: `1h30m`, `90s`, `1.5h`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Duration {
    text: String,
    millis: u64,
}

impl Duration {
    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn millis(&self) -> u64 {
        self.millis
    }

    fn parse(text: &str) -> Option<u64> {
        const UNITS: &[(&str, f64)] = &[("h", 3_600_000.0), ("ms", 1.0), ("m", 60_000.0), ("s", 1000.0)];
        // Units in the order they must come in.
        const ORDER: &[&str] = &["h", "m", "s", "ms"];
        let mut rest = text;
        let mut next_unit = 0;
        let mut millis = 0.0;
        while !rest.is_empty() {
            let end = rest.find(|c: char| !c.is_ascii_digit() && c != '.')?;
            let (number, tail) = rest.split_at(end);
            if !is_number(number) || number.starts_with('.') || number.ends_with('.') {
                return None;
            }
            let &(unit, factor) = UNITS.iter().find(|(unit, _)| tail.starts_with(unit))?;
            let rank = ORDER.iter().position(|u| *u == unit)?;
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
        match Self::parse(&text) {
            Some(millis) => Ok(Self { text, millis }),
            None => Err(InvalidValue::new(
                "duration",
                &text,
                "must be hours, minutes, seconds and milliseconds, in that order (1h30m, 90s, 500ms)",
            )),
        }
    }
}

impl From<Duration> for String {
    fn from(duration: Duration) -> Self {
        duration.text
    }
}

impl AsRef<str> for Duration {
    fn as_ref(&self) -> &str {
        &self.text
    }
}

impl fmt::Display for Duration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// kubelet's image garbage collection settings, checked together as kubelet does.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageGc {
    pub high_threshold_percent: Option<Percent>,
    pub low_threshold_percent: Option<Percent>,
    pub minimum_age: Option<Duration>,
    pub maximum_age: Option<Duration>,
}

impl ImageGc {
    /// kubelet's defaults, which a value left out keeps.
    const DEFAULT_HIGH: u8 = 85;
    const DEFAULT_LOW: u8 = 80;
    const DEFAULT_MINIMUM_AGE_MILLIS: u64 = 2 * 60_000;

    /// kubelet refuses a low threshold not below the high one, and a maximum age (other than 0,
    /// which turns it off) not above the minimum.
    pub fn check(&self) -> Result<(), String> {
        let high = self.high_threshold_percent.map_or(Self::DEFAULT_HIGH, Percent::get);
        let low = self.low_threshold_percent.map_or(Self::DEFAULT_LOW, Percent::get);
        if low >= high {
            return Err(format!(
                "image-gc-low-threshold-percent ({low}) must be below image-gc-high-threshold-percent ({high}); \
                 kubelet's defaults are 80 and 85"
            ));
        }
        let minimum = self
            .minimum_age
            .as_ref()
            .map_or(Self::DEFAULT_MINIMUM_AGE_MILLIS, Duration::millis);
        if let Some(maximum) = &self.maximum_age
            && maximum.millis() != 0
            && maximum.millis() <= minimum
        {
            return Err(format!(
                "image-maximum-gc-age ({maximum}) must be above image-minimum-gc-age (2m by default)"
            ));
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
            "100", "100m", "1.5Gi", "0.5", ".5", "1.", "129e6", "1E3", "1e-3", "10Mi", "1000n", "2k",
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
            assert_eq!(Duration::try_from(text.to_owned()).unwrap().millis(), millis, "{text}");
        }
        for bad in ["", "100", "1m2h", "1h1h", "1.s", ".5s", "1d", "1 h", "9ns", "1ms2s"] {
            assert!(Duration::try_from(bad.to_owned()).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn image_gc_checks() {
        let percent = |n| Some(Percent(n));
        let duration = |text: &str| Some(Duration::try_from(text.to_owned()).unwrap());
        let gc = |high, low| ImageGc {
            high_threshold_percent: high,
            low_threshold_percent: low,
            ..Default::default()
        };
        assert!(ImageGc::default().check().is_ok());
        assert!(gc(percent(90), percent(70)).check().is_ok());
        assert!(
            gc(percent(70), None).check().is_err(),
            "below the default low threshold"
        );
        assert!(gc(None, percent(85)).check().is_err(), "at the default high threshold");
        assert!(gc(percent(50), percent(50)).check().is_err());
        let ages = |minimum, maximum| ImageGc {
            minimum_age: minimum,
            maximum_age: maximum,
            ..Default::default()
        };
        assert!(ages(None, duration("1h")).check().is_ok());
        assert!(ages(None, duration("0s")).check().is_ok(), "0 turns it off");
        assert!(ages(None, duration("1m")).check().is_err());
        assert!(ages(duration("2h"), duration("1h")).check().is_err());
    }

    #[test]
    fn percents_are_numbers_or_strings() {
        #[derive(Deserialize)]
        struct T {
            p: Percent,
        }
        assert_eq!(toml::from_str::<T>("p = 85").unwrap().p.get(), 85);
        assert_eq!(toml::from_str::<T>("p = \"85\"").unwrap().p.get(), 85);
        for bad in ["p = 101", "p = -1", "p = \"x\"", "p = 8.5"] {
            assert!(toml::from_str::<T>(bad).is_err(), "{bad}");
        }
    }
}

//! kubelet's image garbage collection.

use controllers_helpers::InvalidValue;
use serde::{Deserialize, Serialize};

use super::resources::Duration;

/// kubelet's image garbage collection. A value left out keeps kubelet's defaults.
///
/// Written as Bottlerocket's four keys of `[settings.kubernetes]`
/// (`image-gc-high-threshold-percent`, `image-gc-low-threshold-percent`, `image-minimum-gc-age`,
/// `image-maximum-gc-age`); one written alone is paired with kubelet's default for the other.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImageGc {
    /// Disk usage bounds: kubelet's `[80, 85]` when left out.
    pub threshold_percent: Option<ThresholdPercents>,
    /// How long an unused image is kept: at least 2 minutes, and with no maximum, when left
    /// out.
    pub age: Option<ImageAges>,
}

impl ImageGc {
    /// kubelet's defaults, standing for what Bottlerocket's keys leave out.
    const DEFAULT_LOW: Percent = Percent(80);
    const DEFAULT_HIGH: Percent = Percent(85);
    const DEFAULT_MINIMUM_AGE_MILLIS: u64 = 2 * 60_000;

    /// From Bottlerocket's keys, rejecting what kubelet refuses: a low threshold not below the
    /// high one, a maximum age (other than 0, which turns it off) not above the minimum.
    pub(crate) fn from_keys(
        high: Option<Percent>,
        low: Option<Percent>,
        minimum_age: Option<Duration>,
        maximum_age: Option<Duration>,
    ) -> Result<Self, String> {
        let threshold_percent = if high.is_some() || low.is_some() {
            let low = low.unwrap_or(Self::DEFAULT_LOW);
            let high = high.unwrap_or(Self::DEFAULT_HIGH);
            let thresholds = ThresholdPercents::new(low, high).map_err(|_| {
                format!(
                    "image-gc-low-threshold-percent ({}) must be below \
                     image-gc-high-threshold-percent ({}); kubelet's defaults are 80 and 85",
                    low.get(),
                    high.get()
                )
            })?;
            Some(thresholds)
        } else {
            None
        };
        let maximum_age = maximum_age.filter(|maximum| maximum.millis() != 0);
        let age = if minimum_age.is_some() || maximum_age.is_some() {
            let minimum = minimum_age
                .unwrap_or_else(|| Duration::from_millis(Self::DEFAULT_MINIMUM_AGE_MILLIS));
            let ages = ImageAges::new(minimum, maximum_age).map_err(|_| {
                format!(
                    "image-maximum-gc-age ({}) must be above image-minimum-gc-age ({minimum}, \
                     2m by default), or 0s",
                    maximum_age
                        .map(|maximum| maximum.to_string())
                        .unwrap_or_default(),
                )
            })?;
            Some(ages)
        } else {
            None
        };
        Ok(Self {
            threshold_percent,
            age,
        })
    }
}

/// Above `high` percent of disk usage, kubelet collects images until usage is back to `low`.
/// One value, so `low` is below `high` by construction, as kubelet requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ThresholdPercents {
    low: Percent,
    high: Percent,
}

impl ThresholdPercents {
    /// Rejects a `low` threshold that is not below `high`.
    pub(crate) fn new(low: Percent, high: Percent) -> Result<Self, InvalidValue> {
        if low < high {
            Ok(Self { low, high })
        } else {
            Err(InvalidValue::new(
                "image GC thresholds",
                &format!("[{}, {}]", low.get(), high.get()),
                "must be [low, high], low below high",
            ))
        }
    }

    /// The disk usage garbage collection frees down to.
    #[must_use]
    pub fn low(self) -> Percent {
        self.low
    }

    /// The disk usage that always triggers garbage collection.
    #[must_use]
    pub fn high(self) -> Percent {
        self.high
    }
}

/// How long an unused image is kept at least, and at most. One value, so the maximum is above
/// the minimum by construction, as kubelet requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageAges {
    minimum: Duration,
    maximum: Option<Duration>,
}

impl ImageAges {
    /// Rejects a maximum that is not above the minimum.
    pub(crate) fn new(minimum: Duration, maximum: Option<Duration>) -> Result<Self, InvalidValue> {
        match maximum {
            Some(maximum) if maximum.millis() <= minimum.millis() => Err(InvalidValue::new(
                "image ages",
                &format!("[{minimum}, {maximum}]"),
                "must be [minimum] or [minimum, maximum], maximum above minimum",
            )),
            _ => Ok(Self { minimum, maximum }),
        }
    }

    /// How long an unused image is kept, at least.
    #[must_use]
    pub fn minimum(self) -> Duration {
        self.minimum
    }

    /// How long an unused image is kept, at most.
    #[must_use]
    pub fn maximum(self) -> Option<Duration> {
        self.maximum
    }
}

/// A whole percentage, 0 to 100, written as a number or a string (as Bottlerocket accepts).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "PercentKey", into = "u8")]
pub struct Percent(u8);

impl Percent {
    /// The percentage.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u64> for Percent {
    type Error = InvalidValue;

    fn try_from(percent: u64) -> Result<Self, Self::Error> {
        match u8::try_from(percent) {
            Ok(percent) if percent <= 100 => Ok(Self(percent)),
            _ => Err(InvalidValue::new(
                "percentage",
                &percent.to_string(),
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

/// A [`Percent`] as written.
#[derive(Deserialize)]
#[serde(
    untagged,
    expecting = "a whole number from 0 to 100, or a string of one"
)]
enum PercentKey {
    Number(u64),
    Text(String),
}

impl TryFrom<PercentKey> for Percent {
    type Error = InvalidValue;

    fn try_from(key: PercentKey) -> Result<Self, Self::Error> {
        match key {
            PercentKey::Number(number) => Self::try_from(number),
            PercentKey::Text(text) => text.parse::<u64>().map_or_else(
                |_| {
                    Err(InvalidValue::new(
                        "percentage",
                        &text,
                        "must be a whole number from 0 to 100",
                    ))
                },
                Self::try_from,
            ),
        }
    }
}

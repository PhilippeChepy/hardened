//! Pod grace periods in whole seconds.

use controllers_helpers::InvalidValue;
use serde::{Deserialize, Serialize};

/// Seconds a pod gets to stop, from 0 to `i32::MAX`: kubelet's `int32`, and Bottlerocket's type
/// (`evictionMaxPodGracePeriod`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "i64", into = "u32")]
pub struct PodGracePeriod(u32);

impl PodGracePeriod {
    /// The seconds.
    #[must_use]
    pub fn seconds(self) -> u32 {
        self.0
    }
}

impl TryFrom<i64> for PodGracePeriod {
    type Error = InvalidValue;

    fn try_from(seconds: i64) -> Result<Self, Self::Error> {
        i32::try_from(seconds)
            .ok()
            .and_then(|seconds| u32::try_from(seconds).ok())
            .map(Self)
            .ok_or_else(|| {
                InvalidValue::new(
                    "pod grace period",
                    &seconds.to_string(),
                    "must be from 0 to 2147483647 seconds",
                )
            })
    }
}

impl From<PodGracePeriod> for u32 {
    fn from(period: PodGracePeriod) -> Self {
        period.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grace_periods_fit_an_i32() {
        assert_eq!(PodGracePeriod::try_from(30_i64).unwrap().seconds(), 30);
        let max = i64::from(i32::MAX);
        assert_eq!(
            i64::from(PodGracePeriod::try_from(max).unwrap().seconds()),
            max
        );
        for bad in [-1, max + 1] {
            assert!(PodGracePeriod::try_from(bad).is_err(), "{bad}");
        }
    }
}

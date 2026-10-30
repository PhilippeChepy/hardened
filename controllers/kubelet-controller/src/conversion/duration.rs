//! kubelet's durations as `google.protobuf.Duration`.

use controllers_helpers::InvalidValue;

use crate::{Duration, PodGracePeriod};

/// Lossless: a duration is a whole number of milliseconds.
impl From<Duration> for prost_types::Duration {
    fn from(duration: Duration) -> Self {
        let millis = duration.millis();
        Self {
            seconds: i64::try_from(millis / 1000).expect("u64::MAX / 1000 fits in an i64"),
            nanos: i32::try_from(millis % 1000 * 1_000_000).expect("below 10^9"),
        }
    }
}

/// A whole number of milliseconds.
impl TryFrom<prost_types::Duration> for Duration {
    type Error = InvalidValue;

    fn try_from(duration: prost_types::Duration) -> Result<Self, Self::Error> {
        let reject = |reason| {
            InvalidValue::new(
                "duration",
                &format!("{}s {}ns", duration.seconds, duration.nanos),
                reason,
            )
        };
        let seconds =
            u64::try_from(duration.seconds).map_err(|_| reject("must not be negative"))?;
        let nanos = u64::try_from(duration.nanos).map_err(|_| reject("must not be negative"))?;
        if nanos >= 1_000_000_000 {
            return Err(reject("its nanoseconds must be below one second"));
        }
        if nanos % 1_000_000 != 0 {
            return Err(reject("must be a whole number of milliseconds"));
        }
        let millis = seconds
            .checked_mul(1000)
            .and_then(|millis| millis.checked_add(nanos / 1_000_000))
            .ok_or_else(|| reject("is too long"))?;
        Ok(Self::from_millis(millis))
    }
}

/// A whole number of seconds.
impl From<PodGracePeriod> for prost_types::Duration {
    fn from(period: PodGracePeriod) -> Self {
        Self {
            seconds: period.seconds().into(),
            nanos: 0,
        }
    }
}

impl TryFrom<prost_types::Duration> for PodGracePeriod {
    type Error = InvalidValue;

    fn try_from(duration: prost_types::Duration) -> Result<Self, Self::Error> {
        if duration.nanos != 0 {
            return Err(InvalidValue::new(
                "pod grace period",
                &format!("{}s {}ns", duration.seconds, duration.nanos),
                "must be a whole number of seconds",
            ));
        }
        Self::try_from(duration.seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proto(seconds: i64, nanos: i32) -> prost_types::Duration {
        prost_types::Duration { seconds, nanos }
    }

    #[test]
    fn durations_are_whole_milliseconds() {
        let duration = Duration::try_from("1h30m1s5ms".to_owned()).unwrap();
        let message = prost_types::Duration::from(duration);
        assert_eq!(message, proto(5401, 5_000_000));
        assert_eq!(Duration::try_from(message).unwrap(), duration);
        assert_eq!(
            Duration::try_from(proto(5400, 0)).unwrap().to_string(),
            "1h30m",
            "normalized"
        );
        for (bad, why) in [
            (proto(-1, 0), "negative"),
            (proto(0, -1_000_000), "negative nanoseconds"),
            (proto(1, 1), "sub-millisecond"),
            (proto(0, 1_000_000_000), "a second of nanoseconds"),
            (proto(i64::MAX, 0), "overflowing"),
        ] {
            assert!(Duration::try_from(bad).is_err(), "{why} accepted");
        }
    }

    #[test]
    fn grace_periods_are_whole_seconds() {
        let period = PodGracePeriod::try_from(30_i64).unwrap();
        assert_eq!(prost_types::Duration::from(period), proto(30, 0));
        assert_eq!(PodGracePeriod::try_from(proto(30, 0)), Ok(period));
        assert!(PodGracePeriod::try_from(proto(30, 1_000_000)).is_err());
        assert!(PodGracePeriod::try_from(proto(-1, 0)).is_err());
        assert!(PodGracePeriod::try_from(proto(i64::from(i32::MAX) + 1, 0)).is_err());
    }
}

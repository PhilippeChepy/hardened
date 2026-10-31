//! kubelet's graceful node shutdown: how long the node's pods get to stop when it shuts down.

use controllers_helpers::InvalidValue;

use super::resources::Duration;

/// The longest serviced delays a shutdown for (its delay locks'): kubelet would be stopped
/// before the end of a longer period.
const MAX_MILLIS: u64 = 600_000;

/// How long kubelet delays the node's shutdown to stop its pods: the whole period, the last
/// `critical_pods` of it for the critical pods (`system-cluster-critical`,
/// `system-node-critical`), the rest for the others. Not zero (that is off), at most 10 minutes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownGracePeriod {
    total: Duration,
    critical_pods: Duration,
}

impl ShutdownGracePeriod {
    /// `shutdown-grace-period` and `shutdown-grace-period-for-critical-pods`, as Bottlerocket
    /// takes them (both `0s` when left out) and kubelet checks them: none, graceful shutdown off,
    /// when the whole period is `0s`.
    ///
    /// # Errors
    ///
    /// When `total` is above 10 minutes, or `critical_pods` above it.
    pub fn from_settings(
        total: Option<Duration>,
        critical_pods: Option<Duration>,
    ) -> Result<Option<Self>, InvalidValue> {
        let zero = Duration::from_millis(0);
        let (total, critical_pods) = (total.unwrap_or(zero), critical_pods.unwrap_or(zero));
        if critical_pods.millis() > total.millis() {
            return Err(InvalidValue::new(
                "shutdown grace period for critical pods",
                &critical_pods.to_string(),
                "must be at most the shutdown grace period",
            ));
        }
        if total.millis() == 0 {
            return Ok(None);
        }
        if total.millis() > MAX_MILLIS {
            return Err(InvalidValue::new(
                "shutdown grace period",
                &total.to_string(),
                "must be at most 10m (serviced's longest shutdown delay)",
            ));
        }
        Ok(Some(Self {
            total,
            critical_pods,
        }))
    }

    /// The whole period (`shutdownGracePeriod`).
    #[must_use]
    pub fn total(self) -> Duration {
        self.total
    }

    /// Its end, for the critical pods (`shutdownGracePeriodCriticalPods`).
    #[must_use]
    pub fn critical_pods(self) -> Duration {
        self.critical_pods
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn period(
        total: Option<u64>,
        critical_pods: Option<u64>,
    ) -> Result<Option<ShutdownGracePeriod>, InvalidValue> {
        let seconds = |seconds: u64| Duration::from_millis(seconds * 1000);
        ShutdownGracePeriod::from_settings(total.map(seconds), critical_pods.map(seconds))
    }

    #[test]
    fn kubelet_s_checks() {
        let both = period(Some(30), Some(10)).unwrap().unwrap();
        assert_eq!(both.total().to_string(), "30s");
        assert_eq!(both.critical_pods().to_string(), "10s");
        let total = period(Some(30), None).unwrap().unwrap();
        assert_eq!(total.critical_pods().to_string(), "0s");
        for (total, critical) in [
            (None, None),
            (Some(0), None),
            (None, Some(0)),
            (Some(0), Some(0)),
        ] {
            assert_eq!(
                period(total, critical).unwrap(),
                None,
                "{total:?} {critical:?}: off"
            );
        }
        for (total, critical) in [(Some(601), None), (Some(30), Some(31)), (None, Some(10))] {
            assert!(period(total, critical).is_err(), "{total:?} {critical:?}");
        }
    }
}

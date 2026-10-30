//! Soft eviction thresholds.

use std::collections::BTreeMap;

use super::resources::{Duration, EvictionSignal, Threshold};

/// A threshold below which kubelet evicts pods once it lasted its grace period. Together, as
/// kubelet refuses one without the other.
///
/// Written as Bottlerocket's `eviction-soft` and `eviction-soft-grace-period` tables of
/// `[settings.kubernetes]`, keyed by the same signals.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SoftEviction {
    /// Below what the signal triggers eviction.
    pub threshold: Threshold,
    /// How long the threshold must be crossed before evicting.
    pub grace_period: Duration,
}

impl SoftEviction {
    /// Pairs Bottlerocket's two tables by signal. A threshold without grace period is rejected
    /// (kubelet refuses it), and so is a grace period without threshold (ignored, a typo most
    /// likely).
    pub(crate) fn pair(
        thresholds: BTreeMap<EvictionSignal, Threshold>,
        mut grace_periods: BTreeMap<EvictionSignal, Duration>,
    ) -> Result<BTreeMap<EvictionSignal, Self>, String> {
        let mut evictions = BTreeMap::new();
        for (signal, threshold) in thresholds {
            let Some(grace_period) = grace_periods.remove(&signal) else {
                return Err(format!(
                    "eviction-soft.\"{}\" needs its eviction-soft-grace-period",
                    signal.as_str()
                ));
            };
            evictions.insert(
                signal,
                Self {
                    threshold,
                    grace_period,
                },
            );
        }
        if let Some(signal) = grace_periods.keys().next() {
            return Err(format!(
                "eviction-soft-grace-period.\"{}\" has no eviction-soft threshold",
                signal.as_str()
            ));
        }
        Ok(evictions)
    }
}

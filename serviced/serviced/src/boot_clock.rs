//! The time since boot (`CLOCK_BOOTTIME`), which the wall clock may jump over (time-controller
//! sets it).

use std::time::Duration;

use rustix::time::ClockId;

/// The time since boot, suspend included.
#[must_use]
pub fn now() -> Duration {
    let now = rustix::time::clock_gettime(ClockId::Boottime);
    let seconds = u64::try_from(now.tv_sec).unwrap_or_default();
    let nanos = u32::try_from(now.tv_nsec).unwrap_or_default();
    Duration::new(seconds, nanos)
}

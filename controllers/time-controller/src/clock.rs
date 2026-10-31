//! The kernel clock. A large offset steps it; a small one goes to the kernel's PLL, which slews
//! the clock and learns its frequency error, so time never jumps once in sync. Each correction
//! also marks the clock synchronized (clears `STA_UNSYNC`), which lets the kernel copy it to the
//! RTC every 11 minutes; without corrections, the kernel's maximum error grows until it marks
//! the clock unsynchronized again.

use std::io;
use std::mem;
use std::time::Duration;
use std::time::SystemTime;

use time_controller::time;

use crate::packet::Nanos;

/// Offsets this large are stepped. The kernel's PLL takes offsets up to 0.5 s, slewed at most at
/// 500 ppm: 0.4 s takes about 15 minutes.
const STEP_THRESHOLD: Nanos = 400_000_000;
/// The shortest poll interval, as a power of two seconds: 32 s.
pub const MIN_POLL: u32 = 5;
/// The longest poll interval, as a power of two seconds: 2048 s (34 min).
pub const MAX_POLL: u32 = 11;

/// How the clock is corrected by an offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Correction {
    /// Set the clock at once ([`step`]).
    Step(Nanos),
    /// Give the offset to the kernel's PLL ([`slew`]).
    Slew(Nanos),
}

impl Correction {
    /// Steps offsets of at least [`STEP_THRESHOLD`], slews the others.
    #[must_use]
    pub fn for_offset(offset: Nanos) -> Self {
        if offset.abs() >= STEP_THRESHOLD {
            Self::Step(offset)
        } else {
            Self::Slew(offset)
        }
    }
}

/// The poll interval after a correction: back to the shortest after a step, longer while the
/// clock stays within 10 ms, shorter past 50 ms.
#[must_use]
pub fn next_poll(poll: u32, correction: Correction) -> u32 {
    match correction {
        Correction::Step(_) => MIN_POLL,
        Correction::Slew(offset) => match offset.unsigned_abs() {
            0..10_000_000 => (poll + 1).min(MAX_POLL),
            10_000_000..50_000_000 => poll,
            _ => poll.saturating_sub(1).max(MIN_POLL),
        },
    }
}

/// Applies `correction`, measured with the error bounds `max_error` and `estimated_error`, at
/// the poll interval `poll`: a step resets the PLL's time constant to the shortest.
pub fn apply(
    correction: Correction,
    poll: u32,
    max_error: Duration,
    estimated_error: Duration,
) -> io::Result<()> {
    match correction {
        Correction::Step(offset) => {
            step(offset).and_then(|()| slew(0, MIN_POLL, max_error, estimated_error))
        }
        Correction::Slew(offset) => slew(offset, poll, max_error, estimated_error),
    }
}

/// The time, in nanoseconds since the Unix epoch.
#[must_use]
pub fn now() -> Nanos {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    since_epoch.as_nanos().try_into().unwrap_or(Nanos::MAX)
}

/// Steps the clock by `offset`.
pub fn step(offset: Nanos) -> io::Result<()> {
    let mut timex = timex();
    timex.modes = libc::ADJ_SETOFFSET | libc::ADJ_NANO;
    // A negative offset is negative seconds plus positive nanoseconds (in `tv_usec`, with
    // ADJ_NANO).
    timex.time.tv_sec = offset.div_euclid(1_000_000_000);
    timex.time.tv_usec = offset.rem_euclid(1_000_000_000);
    adjust(&mut timex).map(drop)
}

/// Gives `offset` to the kernel's PLL, with the poll interval (its time constant) and the error
/// bounds of the measurement, and marks the clock synchronized.
pub fn slew(
    offset: Nanos,
    poll: u32,
    max_error: Duration,
    estimated_error: Duration,
) -> io::Result<()> {
    let mut timex = timex();
    timex.modes = libc::ADJ_STATUS
        | libc::ADJ_NANO
        | libc::ADJ_OFFSET
        | libc::ADJ_TIMECONST
        | libc::ADJ_MAXERROR
        | libc::ADJ_ESTERROR;
    timex.status = libc::STA_PLL;
    timex.offset = offset;
    // The PLL's time constant is the poll exponent less 4, as ntpd and systemd-timesyncd set it.
    timex.constant = i64::from(poll) - 4;
    timex.maxerror = max_error.as_micros().try_into().unwrap_or(i64::MAX);
    timex.esterror = estimated_error.as_micros().try_into().unwrap_or(i64::MAX);
    adjust(&mut timex).map(drop)
}

/// Reads what the kernel knows of the clock's synchronization (needs no privilege).
pub fn state() -> io::Result<time::Clock> {
    let mut timex = timex();
    let clock = adjust(&mut timex)?;
    let micros = |value: i64| value.max(0).unsigned_abs();
    Ok(time::Clock {
        // STA_UNSYNC clear, no TIME_ERROR.
        synchronized: clock != libc::TIME_ERROR && timex.status & libc::STA_UNSYNC == 0,
        estimated_error_us: micros(timex.esterror),
        max_error_us: micros(timex.maxerror),
        // In units of 2^-16 ppm.
        frequency_ppm: timex.freq as f64 / 65536.0,
    })
}

fn timex() -> libc::timex {
    // SAFETY: `timex` is plain integers; all zeros is valid (no mode: read only).
    unsafe { mem::zeroed() }
}

/// `clock_adjtime(CLOCK_REALTIME)`: returns the clock state (`TIME_OK`...).
///
/// A safe wrapper of the system call, which neither std nor rustix provides.
fn adjust(timex: &mut libc::timex) -> io::Result<i32> {
    // SAFETY: the kernel reads and writes a `struct timex` through the pointer, and `timex` is one,
    // valid and exclusively borrowed for the duration of the call; the call keeps no reference to
    // it.
    match unsafe { libc::clock_adjtime(libc::CLOCK_REALTIME, timex) } {
        -1 => Err(io::Error::last_os_error()),
        state => Ok(state),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn steps_only_large_offsets() {
        assert_eq!(
            Correction::for_offset(399_999_999),
            Correction::Slew(399_999_999)
        );
        assert_eq!(
            Correction::for_offset(-400_000_000),
            Correction::Step(-400_000_000)
        );
    }

    #[test]
    fn polls_less_often_while_in_sync() {
        assert_eq!(
            next_poll(MIN_POLL, Correction::Slew(-2_000_000)),
            MIN_POLL + 1
        );
        assert_eq!(next_poll(MAX_POLL, Correction::Slew(1_000)), MAX_POLL);
        assert_eq!(next_poll(8, Correction::Slew(20_000_000)), 8);
        assert_eq!(next_poll(8, Correction::Slew(-80_000_000)), 7);
        assert_eq!(next_poll(MIN_POLL, Correction::Slew(80_000_000)), MIN_POLL);
        assert_eq!(
            next_poll(MAX_POLL, Correction::Step(1_000_000_000)),
            MIN_POLL
        );
    }

    #[test]
    fn reads_the_clock_state() {
        let state = state().unwrap();
        assert!(
            state.frequency_ppm.abs() <= 512.0,
            "the kernel bounds the frequency correction to 500 ppm: {state:?}"
        );
    }
}

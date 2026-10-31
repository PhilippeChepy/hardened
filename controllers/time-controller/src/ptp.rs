//! The hypervisor's PTP clock (`ptp_kvm`): on KVM, a clock the host keeps, read in nanoseconds
//! without the network. Its offset from the system clock is measured with `PTP_SYS_OFFSET`, which
//! reads it between readings of the system clock: the tightest pair bounds the reading.

use std::fs;
use std::io;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::ioctl;

use crate::clock;
use crate::clock::Correction;
use crate::measurement::Measurement;
use crate::measurement::Source;
use crate::packet::Nanos;

/// Where the kernel lists its virtual PTP clocks (a NIC's would be under its device).
const VIRTUAL_CLOCKS: &str = "/sys/devices/virtual/ptp";
/// The name `ptp_kvm` gives its clock.
const KVM_CLOCK_NAME: &str = "KVM virtual PTP";
/// Readings per measurement, at most the kernel's `PTP_MAX_SAMPLES` (25).
const SAMPLES: u32 = 10;
/// The poll interval, as a power of two seconds: 16 s. Reading the clock costs nothing, and the
/// kernel's PLL follows it closely with that time constant.
pub const POLL: u32 = 4;

/// `struct ptp_clock_time`.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct ClockTime {
    sec: i64,
    nsec: u32,
    reserved: u32,
}

impl ClockTime {
    #[must_use]
    fn nanos(self) -> Nanos {
        self.sec
            .saturating_mul(1_000_000_000)
            .saturating_add(Nanos::from(self.nsec))
    }
}

/// `struct ptp_sys_offset`: the system clock, then the PTP clock, then the system clock... for
/// `n_samples` readings of the PTP clock.
#[repr(C)]
#[derive(Debug)]
struct SysOffset {
    n_samples: u32,
    rsv: [u32; 3],
    ts: [ClockTime; 2 * 25 + 1],
}

/// `PTP_SYS_OFFSET`: `_IOW('=', 5, struct ptp_sys_offset)`, which the kernel also writes back.
const PTP_SYS_OFFSET: ioctl::Opcode = ioctl::opcode::write::<SysOffset>(b'=', 5);

/// The KVM PTP clock, opened.
#[derive(Debug)]
pub struct PtpClock {
    /// Its device, `/dev/ptp<N>`.
    pub device: PathBuf,
    /// The name its driver gives it.
    pub name: String,
    file: OwnedFd,
}

/// An offset of the PTP clock from the system clock, and how long the system clock took to read
/// it (the bound of the measurement), in nanoseconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offset {
    /// Positive: the system clock is behind.
    pub offset: Nanos,
    pub delay: Nanos,
}

impl PtpClock {
    /// The KVM PTP clock, if the hypervisor gives one.
    ///
    /// # Errors
    ///
    /// When there is one but it cannot be opened.
    pub fn find() -> io::Result<Option<Self>> {
        Self::find_in(Path::new(VIRTUAL_CLOCKS), Path::new("/dev"))
    }

    fn find_in(clocks: &Path, dev: &Path) -> io::Result<Option<Self>> {
        let entries = match fs::read_dir(clocks) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            let name = match fs::read_to_string(entry.path().join("clock_name")) {
                Ok(name) => name.trim().to_owned(),
                Err(_) => continue,
            };
            if name != KVM_CLOCK_NAME {
                continue;
            }
            let device = dev.join(entry.file_name());
            let file = rustix::fs::open(&device, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())?;
            return Ok(Some(Self { device, name, file }));
        }
        Ok(None)
    }

    /// The PTP clock's offset from the system clock.
    ///
    /// # Errors
    ///
    /// When the kernel cannot read it.
    pub fn offset(&self) -> io::Result<Offset> {
        let mut readings = SysOffset {
            n_samples: SAMPLES,
            rsv: [0; 3],
            ts: [ClockTime::default(); 51],
        };
        // SAFETY: `PTP_SYS_OFFSET` takes a `struct ptp_sys_offset`, which `SysOffset` mirrors
        // (`repr(C)`, the same fields and sizes); the kernel fills it in place.
        unsafe {
            ioctl::ioctl(
                &self.file,
                ioctl::Updater::<PTP_SYS_OFFSET, SysOffset>::new(&mut readings),
            )?;
        }
        best(&readings.ts, readings.n_samples)
            .ok_or_else(|| io::Error::other("the PTP clock returned no reading"))
    }
}

impl PtpClock {
    /// Corrects the clock with the PTP clock's offset: the correction, or why there is none.
    /// `synchronized` is whether the previous round corrected it, to log only changes.
    pub fn round(&self, synchronized: bool) -> Result<Measurement, String> {
        let device = self.device.display().to_string();
        let measured = self
            .offset()
            .map_err(|e| format!("reading the PTP clock {device}: {e}"))?;
        let correction = Correction::for_offset(measured.offset);
        let bound = std::time::Duration::from_nanos(measured.delay.unsigned_abs());
        clock::apply(correction, POLL, bound, bound / 2)
            .map_err(|e| format!("cannot correct the clock: {e}"))?;
        let offset_ns = measured.offset;
        if let Correction::Step(_) = correction {
            tracing::warn!(device, offset_ns, "clock stepped");
        }
        if synchronized {
            tracing::debug!(
                device,
                offset_ns,
                delay_ns = measured.delay,
                "clock corrected"
            );
        } else {
            tracing::info!(device, offset_ns, "clock synchronized with the PTP clock");
        }
        Ok(Measurement {
            source: Source::Ptp {
                device,
                name: self.name.clone(),
            },
            offset_ns,
            delay_ns: measured.delay,
            stepped: matches!(correction, Correction::Step(_)),
            at_unix_ns: clock::now(),
        })
    }
}

/// The reading of `samples` taken in the shortest time: the PTP clock against the midpoint of
/// the system clock's readings around it.
#[must_use]
fn best(ts: &[ClockTime], samples: u32) -> Option<Offset> {
    let count = usize::try_from(samples).ok()?;
    (0..count)
        .filter_map(|i| {
            let (before, ptp, after) = (ts.get(2 * i)?, ts.get(2 * i + 1)?, ts.get(2 * i + 2)?);
            let (before, after) = (before.nanos(), after.nanos());
            let delay = after.checked_sub(before).filter(|delay| *delay >= 0)?;
            let midpoint = before.saturating_add(delay / 2);
            Some(Offset {
                offset: ptp.nanos().saturating_sub(midpoint),
                delay,
            })
        })
        .min_by_key(|offset| offset.delay)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(nanos: Nanos) -> ClockTime {
        ClockTime {
            sec: nanos.div_euclid(1_000_000_000),
            nsec: u32::try_from(nanos.rem_euclid(1_000_000_000)).unwrap(),
            reserved: 0,
        }
    }

    #[test]
    fn the_layout_matches_the_kernel() {
        // struct ptp_sys_offset: 16 bytes, then 51 struct ptp_clock_time of 16 bytes.
        assert_eq!(size_of::<SysOffset>(), 16 + 51 * 16);
        assert_eq!(PTP_SYS_OFFSET, 0x4340_3d05);
    }

    #[test]
    fn keeps_the_tightest_reading() {
        // System, PTP, system...: the PTP clock 1 ms ahead; the second reading is the tightest.
        let ts = [
            at(1_000),
            at(1_000_000 + 1_300),
            at(2_000),
            at(1_000_000 + 2_100),
            at(2_200),
            at(1_000_000 + 2_800),
            at(3_400),
        ];
        let best = best(&ts, 3).unwrap();
        assert_eq!(
            best,
            Offset {
                offset: 1_000_000,
                delay: 200
            }
        );
    }

    #[test]
    fn finds_the_kvm_clock_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let (clocks, dev) = (dir.path().join("ptp"), dir.path().join("dev"));
        for (clock, name) in [("ptp0", "some NIC"), ("ptp1", "KVM virtual PTP")] {
            fs::create_dir_all(clocks.join(clock)).unwrap();
            fs::write(clocks.join(clock).join("clock_name"), format!("{name}\n")).unwrap();
        }
        fs::create_dir_all(&dev).unwrap();
        fs::write(dev.join("ptp1"), "").unwrap();
        let clock = PtpClock::find_in(&clocks, &dev).unwrap().unwrap();
        assert_eq!(clock.device, dev.join("ptp1"));
        assert_eq!(clock.name, "KVM virtual PTP");
        assert!(
            PtpClock::find_in(&dir.path().join("none"), &dev)
                .unwrap()
                .is_none()
        );
    }
}

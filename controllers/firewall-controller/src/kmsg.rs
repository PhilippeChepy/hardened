//! The kernel's log (`/dev/kmsg`), read on a thread of its own for the table's log lines: those
//! logged from now on, timed as they are read (no monotonic clock: rustix's would read the
//! auxiliary vector with `prctl(PR_GET_AUXV)`, which the sandbox denies).

use std::fs::File;
use std::io;
use std::io::Read as _;
use std::io::Seek as _;
use std::io::SeekFrom;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::SystemTime;

use firewall_controller::drop_log::LoggedPacket;
use firewall_controller::drop_log::RecentBlocked;

/// The kernel's log.
const KMSG: &str = "/dev/kmsg";
/// A record's most: Linux's are under 1 KiB of text.
const RECORD_LEN: usize = 8192;

/// Reads the kernel's log from its newest record on, forever, counting the packets the table's
/// log rules logged into `recent`. Without the log, says so and reads nothing.
pub fn spawn(recent: Arc<Mutex<RecentBlocked>>) {
    let mut file = match File::open(KMSG) {
        Ok(file) => file,
        Err(error) => {
            tracing::warn!(%error, "no {KMSG}: what is blocked is not reported");
            return;
        }
    };
    // The records logged before are not timed: skipped.
    if let Err(error) = file.seek(SeekFrom::End(0)) {
        tracing::debug!(%error, "{KMSG} cannot skip to its end: its older records count too");
    }
    let spawned = std::thread::Builder::new()
        .name("kmsg".to_owned())
        .spawn(move || read(file, &recent));
    if let Err(error) = spawned {
        tracing::warn!(%error, "reading {KMSG}: what is blocked is not reported");
    }
}

fn read(mut file: File, recent: &Mutex<RecentBlocked>) {
    let mut record = vec![0; RECORD_LEN];
    loop {
        match file.read(&mut record) {
            Ok(0) => return,
            Ok(len) => {
                let text = String::from_utf8_lossy(&record[..len]);
                if let Some(packet) = LoggedPacket::parse_record(&text)
                    && let Ok(mut recent) = recent.lock()
                {
                    recent.record(packet, SystemTime::now());
                }
            }
            // Records overwritten before they were read: the next one follows.
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::PIPE.raw_os_error()) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                tracing::warn!(%error, "reading {KMSG}: what is blocked is no longer reported");
                return;
            }
        }
    }
}

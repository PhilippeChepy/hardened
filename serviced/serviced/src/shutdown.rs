//! The end of a shutdown: once the services stopped, the processes they left are killed
//! ([`terminate_all`]); once the services undid what they did with their `exec-stop`
//! (storage-controller unmounts `/var`), the kernel reboots or powers off ([`finish`]).

use std::time::Duration;

use rustix::system::RebootCommand;
use tracing::{info, warn};

use crate::logging;
use crate::power::PowerRequest;
use crate::process;
use crate::process::Reaper;

/// Time left to the remaining processes between SIGTERM and SIGKILL: containers (workloads,
/// kubelet's pods) outlive the services that started them.
const TERM_GRACE: Duration = Duration::from_secs(20);
/// Time left to the console to show the last lines before the reboot or power-off.
const CONSOLE_FLUSH: Duration = Duration::from_secs(2);

/// Signals every process but serviced (SIGTERM, then SIGKILL after [`TERM_GRACE`]), waiting for
/// `reaper` to collect them.
pub async fn terminate_all(reaper: &Reaper) {
    if process::no_children() {
        return;
    }
    info!("terminating the remaining processes");
    kill_all(libc::SIGTERM);
    if reaper.wait_for_no_children(TERM_GRACE).await {
        return;
    }
    warn!("killing the remaining processes");
    kill_all(libc::SIGKILL);
    if !reaper.wait_for_no_children(Duration::from_secs(2)).await {
        warn!("some processes survived SIGKILL");
    }
}

/// Sends `signal` to every process serviced may signal, but serviced itself (`kill(-1, signal)`).
fn kill_all(signal: i32) {
    // rustix has no safe wrapper for pid -1 (every process).
    // SAFETY: kill(2) takes no pointer and has no memory-safety precondition; with pid -1 it
    // signals every process serviced may signal, but serviced itself.
    unsafe {
        libc::kill(-1, signal);
    }
}

/// Flushes the file systems, then reboots or powers off. Never returns.
pub fn finish(request: PowerRequest) -> ! {
    rustix::fs::sync();
    let command = match request {
        PowerRequest::Reboot => RebootCommand::Restart,
        PowerRequest::PowerOff => RebootCommand::PowerOff,
    };
    info!(?request, "goodbye");
    logging::flush_console(CONSOLE_FLUSH);
    let _ = rustix::system::reboot(command);
    // reboot(2) does not return on success; if it failed there is nothing left to do.
    loop {
        std::thread::park();
    }
}

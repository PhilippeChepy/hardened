//! Power management: requests from signals and the ACPI power button, and the final reboot.
//!
//! Signals follow the classic init conventions: SIGINT (Ctrl-Alt-Del, once disabled in the
//! kernel) and SIGTERM reboot, SIGPWR and SIGUSR2 power off. Cloud "stop" actions press the ACPI
//! power button, read here from its evdev device, without udev or acpid.

use std::fs::File;
use std::io::Read;
use std::path::PathBuf;

use rustix::mount::UnmountFlags;
use rustix::system::RebootCommand;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::mpsc;
use tracing::{info, warn};

use crate::machine::PowerRequest;

const EV_KEY: u16 = 0x01;
const KEY_POWER: u16 = 116;
/// `struct input_event` on 64-bit: timeval (16 bytes), type, code, value.
const INPUT_EVENT_SIZE: usize = 24;

/// Forwards power requests from signals and power buttons to `tx`.
pub fn watch(tx: mpsc::Sender<PowerRequest>) -> anyhow::Result<()> {
    // Ctrl-Alt-Del sends SIGINT to init instead of rebooting immediately.
    rustix::system::reboot(RebootCommand::CadOff)?;

    for (kind, request) in [
        (SignalKind::interrupt(), PowerRequest::Reboot),
        (SignalKind::terminate(), PowerRequest::Reboot),
        (
            SignalKind::from_raw(rustix::process::Signal::POWER.as_raw()),
            PowerRequest::PowerOff,
        ),
        (SignalKind::user_defined2(), PowerRequest::PowerOff),
    ] {
        let mut stream = signal(kind)?;
        let tx = tx.clone();
        tokio::spawn(async move {
            while stream.recv().await.is_some() {
                let _ = tx.send(request).await;
            }
        });
    }

    for device in power_buttons() {
        let tx = tx.clone();
        std::thread::Builder::new().name("power-button".into()).spawn(move || {
            if let Err(e) = read_power_button(&device, &tx) {
                warn!(device = %device.display(), "power button: {e}");
            }
        })?;
    }
    Ok(())
}

/// Event devices named like ACPI power buttons.
fn power_buttons() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/sys/class/input") else {
        return Vec::new();
    };
    entries
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("event"))
        .filter(|e| {
            std::fs::read_to_string(e.path().join("device/name")).is_ok_and(|name| name.trim() == "Power Button")
        })
        .map(|e| PathBuf::from("/dev/input").join(e.file_name()))
        .collect()
}

fn read_power_button(device: &PathBuf, tx: &mpsc::Sender<PowerRequest>) -> std::io::Result<()> {
    let mut file = File::open(device)?;
    info!(device = %device.display(), "watching power button");
    let mut event = [0u8; INPUT_EVENT_SIZE];
    loop {
        file.read_exact(&mut event)?;
        let kind = u16::from_ne_bytes([event[16], event[17]]);
        let code = u16::from_ne_bytes([event[18], event[19]]);
        let value = i32::from_ne_bytes([event[20], event[21], event[22], event[23]]);
        if kind == EV_KEY && code == KEY_POWER && value == 1 {
            info!("power button pressed");
            let _ = tx.blocking_send(PowerRequest::PowerOff);
        }
    }
}

/// Flushes and unmounts the state partition, then reboots or powers off. Never returns.
pub fn finish(request: PowerRequest) -> ! {
    rustix::fs::sync();
    if let Err(e) = rustix::mount::unmount("/var", UnmountFlags::empty()) {
        warn!("unmounting /var: {e}; detaching it");
        let _ = rustix::mount::unmount("/var", UnmountFlags::DETACH);
    }
    rustix::fs::sync();
    let command = match request {
        PowerRequest::Reboot => RebootCommand::Restart,
        PowerRequest::PowerOff => RebootCommand::PowerOff,
    };
    info!(?request, "goodbye");
    let _ = rustix::system::reboot(command);
    // reboot(2) does not return on success; if it failed there is nothing left to do.
    loop {
        std::thread::park();
    }
}

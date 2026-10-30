//! Power requests from signals and the ACPI power button.
//!
//! Signals follow the classic init conventions: SIGINT (Ctrl-Alt-Del, once disabled in the kernel)
//! and SIGTERM reboot, SIGPWR and SIGUSR2 power off. Cloud "stop" actions press the ACPI power
//! button, read here from its evdev device, without udev or acpid. serviced's API is the third
//! source (`Reboot`, `PowerOff`).

use std::io;
use std::path::{Path, PathBuf};

use rustix::process::Signal;
use rustix::system::RebootCommand;
use tokio::io::Interest;
use tokio::io::unix::AsyncFd;
use tokio::signal::unix::{self, SignalKind};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// What the machine is to do once the services stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PowerRequest {
    Reboot,
    PowerOff,
}

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
            SignalKind::from_raw(Signal::POWER.as_raw()),
            PowerRequest::PowerOff,
        ),
        (SignalKind::user_defined2(), PowerRequest::PowerOff),
    ] {
        let mut stream = unix::signal(kind)?;
        let tx = tx.clone();
        tokio::spawn(async move {
            while stream.recv().await.is_some() {
                let _ = tx.send(request).await;
            }
        });
    }

    for device in power_buttons() {
        let tx = tx.clone();
        tokio::spawn(async move {
            if let Err(e) = read_power_button(&device, &tx).await {
                warn!(device = %device.display(), "power button: {e}");
            }
        });
    }
    Ok(())
}

/// Event devices named like ACPI power buttons.
#[must_use]
fn power_buttons() -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir("/sys/class/input") else {
        return Vec::new();
    };
    let readable = entries.filter_map(Result::ok);
    let mut devices = Vec::new();
    for entry in readable {
        let is_event = entry.file_name().to_string_lossy().starts_with("event");
        let name = std::fs::read_to_string(entry.path().join("device/name")).unwrap_or_default();
        if is_event && name.trim() == "Power Button" {
            devices.push(Path::new("/dev/input").join(entry.file_name()));
        }
    }
    devices
}

/// Sends a power-off request to `tx` whenever the power button `device` is pressed; returns only
/// on a read error.
async fn read_power_button(device: &Path, tx: &mpsc::Sender<PowerRequest>) -> io::Result<()> {
    use std::fs::OpenOptions;
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(device)?;
    // SAFETY: the `AsyncFd` owns the file, so its fd stays open, the same, until it is dropped.
    let file = unsafe { AsyncFd::register_with_interest(file, Interest::READABLE) }?;
    info!(device = %device.display(), "watching power button");
    let mut event = [0u8; INPUT_EVENT_SIZE];
    loop {
        let mut ready = file.readable().await?;
        // evdev reads whole events.
        let read = match ready.try_io(|file| file.get_ref().read(&mut event)) {
            Ok(read) => read?,
            Err(_would_block) => continue,
        };
        if read != INPUT_EVENT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("read {read} bytes of an event"),
            ));
        }
        let kind = u16::from_ne_bytes([event[16], event[17]]);
        let code = u16::from_ne_bytes([event[18], event[19]]);
        let value = i32::from_ne_bytes([event[20], event[21], event[22], event[23]]);
        if kind == EV_KEY && code == KEY_POWER && value == 1 {
            info!("power button pressed");
            let _ = tx.send(PowerRequest::PowerOff).await;
        }
    }
}

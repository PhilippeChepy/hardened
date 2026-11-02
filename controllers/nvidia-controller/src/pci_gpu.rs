//! The NVIDIA GPUs on the PCI bus, from sysfs.

use std::fs;
use std::io;
use std::path::Path;

/// NVIDIA's PCI vendor ID.
const NVIDIA: &str = "0x10de";
/// The PCI display controller class (VGA, 3D...), the first byte of `class`.
const DISPLAY_CLASS: &str = "0x03";

/// An NVIDIA GPU on the PCI bus.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PciGpu {
    /// Domain:bus:device.function, its sysfs name.
    pub address: String,
    /// The PCI device ID.
    pub device_id: u32,
}

/// The NVIDIA GPUs of `devices` (`/sys/bus/pci/devices`), by address.
///
/// # Errors
///
/// When the directory cannot be read.
pub fn scan(devices: &Path) -> io::Result<Vec<PciGpu>> {
    let mut gpus = Vec::new();
    for entry in fs::read_dir(devices)? {
        let entry = entry?;
        let read = |file: &str| fs::read_to_string(entry.path().join(file)).unwrap_or_default();
        if read("vendor").trim() != NVIDIA || !read("class").trim().starts_with(DISPLAY_CLASS) {
            continue;
        }
        let device = read("device");
        let device_id = u32::from_str_radix(device.trim().trim_start_matches("0x"), 16)
            .map_err(|_| io::Error::other(format!("invalid PCI device ID {device:?}")))?;
        gpus.push(PciGpu {
            address: entry.file_name().to_string_lossy().into_owned(),
            device_id,
        });
    }
    gpus.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(gpus)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device(dir: &Path, address: &str, vendor: &str, class: &str, device: &str) {
        let path = dir.join(address);
        fs::create_dir_all(&path).unwrap();
        for (file, value) in [("vendor", vendor), ("class", class), ("device", device)] {
            fs::write(path.join(file), format!("{value}\n")).unwrap();
        }
    }

    #[test]
    fn finds_nvidia_display_controllers_only() {
        let dir = tempfile::tempdir().unwrap();
        device(dir.path(), "0000:00:05.0", "0x10de", "0x030200", "0x20b5");
        device(dir.path(), "0000:00:03.0", "0x10de", "0x030000", "0x1eb8");
        device(dir.path(), "0000:00:04.0", "0x10de", "0x068000", "0x22a3");
        device(dir.path(), "0000:00:02.0", "0x1af4", "0x020000", "0x1041");
        assert_eq!(
            scan(dir.path()).unwrap(),
            [
                PciGpu {
                    address: "0000:00:03.0".into(),
                    device_id: 0x1eb8
                },
                PciGpu {
                    address: "0000:00:05.0".into(),
                    device_id: 0x20b5
                },
            ],
            "an NVSwitch (0x0680) is no GPU"
        );
    }
}

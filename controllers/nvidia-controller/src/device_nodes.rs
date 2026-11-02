//! The device nodes of NVIDIA's driver, which it does not make itself (there is no udev):
//! `/dev/nvidiactl` and `/dev/nvidia<minor>` (major 195), `/dev/nvidia-uvm` and
//! `/dev/nvidia-uvm-tools` (the major `nvidia-uvm` got), readable and writable by all, as
//! NVIDIA's own tools make them: containers only get those they are given. And MIG's capability
//! nodes, `/dev/nvidia-caps/nvidia-cap<minor>` (the major `nvidia-caps` got, the minors of
//! `/proc/driver/nvidia-caps/mig-minors`): managing MIG (`config`) and monitoring it (`monitor`)
//! for root only, an instance's access for all, as NVIDIA's defaults have them.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;

use anyhow::Context as _;
use anyhow::bail;
use rustix::fs::FileType;
use rustix::fs::Mode;
use rustix::io::Errno;

/// The major of the GPUs and of the control device.
const NVIDIA_MAJOR: u32 = 195;
/// The control device's minor.
const CONTROL_MINOR: u32 = 255;

/// Makes the nodes in `dev` from what the loaded driver says in `proc` (`/proc`): its GPUs'
/// minors, by PCI address, and nvidia-uvm's major.
///
/// # Errors
///
/// When the driver's procfs files cannot be read, or a node cannot be made.
pub fn make(dev: &Path, proc: &Path) -> anyhow::Result<BTreeMap<String, u32>> {
    let minors = gpu_minors(&proc.join("driver/nvidia/gpus"))?;
    let devices = fs::read_to_string(proc.join("devices")).context("/proc/devices")?;
    let Some(uvm) = major(&devices, "nvidia-uvm") else {
        bail!("nvidia-uvm has no major in /proc/devices");
    };
    let mut nodes = vec![
        ("nvidiactl".to_owned(), NVIDIA_MAJOR, CONTROL_MINOR),
        ("nvidia-uvm".to_owned(), uvm, 0),
        ("nvidia-uvm-tools".to_owned(), uvm, 1),
    ];
    nodes.extend(
        minors
            .values()
            .map(|&minor| (format!("nvidia{minor}"), NVIDIA_MAJOR, minor)),
    );
    for (name, major, minor) in nodes {
        node(&dev.join(&name), major, minor, 0o666).with_context(|| format!("/dev/{name}"))?;
    }
    make_capabilities(dev, proc, &devices)?;
    Ok(minors)
}

/// Makes MIG's capability nodes in `dev/nvidia-caps`, when the driver has them.
fn make_capabilities(dev: &Path, proc: &Path, devices: &str) -> anyhow::Result<()> {
    let path = proc.join("driver/nvidia-caps/mig-minors");
    let capabilities = match fs::read_to_string(&path) {
        Ok(capabilities) => capabilities,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e).context(path.display().to_string()),
    };
    let Some(major) = major(devices, "nvidia-caps") else {
        bail!("nvidia-caps has no major in /proc/devices");
    };
    let dir = dev.join("nvidia-caps");
    fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
    for (capability, minor) in capability_minors(&capabilities)? {
        let mode = match capability {
            "config" | "monitor" => 0o400,
            _ => 0o444,
        };
        let path = dir.join(format!("nvidia-cap{minor}"));
        node(&path, major, minor, mode).with_context(|| path.display().to_string())?;
    }
    Ok(())
}

/// The minor of each capability of `mig-minors` (`config 1`, `gpu0/gi1/access 12`...).
fn capability_minors(text: &str) -> anyhow::Result<Vec<(&str, u32)>> {
    (text.lines())
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let minor = line
                .split_once(' ')
                .and_then(|(capability, minor)| Some((capability, minor.trim().parse().ok()?)));
            minor.with_context(|| format!("mig-minors: unexpected line {line:?}"))
        })
        .collect()
}

/// A character device node of `mode`; one there already is left, its mode set.
fn node(path: &Path, major: u32, minor: u32, mode: u32) -> rustix::io::Result<()> {
    let device = rustix::fs::makedev(major, minor);
    match rustix::fs::mknodat(
        rustix::fs::CWD,
        path,
        FileType::CharacterDevice,
        Mode::from_raw_mode(mode),
        device,
    ) {
        Ok(()) | Err(Errno::EXIST) => {}
        Err(e) => return Err(e),
    }
    // mknod applies the umask.
    rustix::fs::chmod(path, Mode::from_raw_mode(mode))
}

/// The minor of each GPU the driver probed, by PCI address (`gpus/<address>/information`).
fn gpu_minors(gpus: &Path) -> anyhow::Result<BTreeMap<String, u32>> {
    let mut minors = BTreeMap::new();
    for entry in fs::read_dir(gpus).with_context(|| gpus.display().to_string())? {
        let entry = entry?;
        let information = fs::read_to_string(entry.path().join("information"))?;
        let minor = information
            .lines()
            .find_map(|line| line.strip_prefix("Device Minor:"))
            .and_then(|minor| minor.trim().parse().ok())
            .with_context(|| format!("no device minor for {}", entry.path().display()))?;
        minors.insert(entry.file_name().to_string_lossy().into_owned(), minor);
    }
    Ok(minors)
}

/// The major of the character device `name` in `/proc/devices`.
#[must_use]
fn major(devices: &str, name: &str) -> Option<u32> {
    devices
        .lines()
        .skip_while(|line| *line != "Character devices:")
        .take_while(|line| !line.is_empty())
        .filter_map(|line| line.trim().split_once(' '))
        .find(|(_, device)| *device == name)
        .and_then(|(major, _)| major.parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn majors_of_character_devices_only() {
        let devices = "Character devices:\n  1 mem\n195 nvidia\n507 nvidia-uvm\n\n\
                       Block devices:\n507 nvidia-uvm\n";
        assert_eq!(major(devices, "nvidia-uvm"), Some(507));
        assert_eq!(major(devices, "nvidia"), Some(195));
        assert_eq!(major(devices, "nvidia-caps"), None);
    }

    #[test]
    fn capability_minors_of_mig() {
        let minors =
            capability_minors("config 1\nmonitor 2\ngpu0/gi0/access 3\ngpu0/gi0/ci0/access 4\n")
                .unwrap();
        assert_eq!(minors[0], ("config", 1));
        assert_eq!(minors[3], ("gpu0/gi0/ci0/access", 4));
        assert!(capability_minors("config one\n").is_err());
    }

    #[test]
    fn minors_by_pci_address() {
        let dir = tempfile::tempdir().unwrap();
        for (address, minor) in [("0000:00:05.0", 1), ("0000:00:03.0", 0)] {
            let gpu = dir.path().join(address);
            fs::create_dir_all(&gpu).unwrap();
            fs::write(
                gpu.join("information"),
                format!("Model: \t\t NVIDIA L4\nIRQ:   \t\t 40\nDevice Minor: \t {minor}\n"),
            )
            .unwrap();
        }
        let minors = gpu_minors(dir.path()).unwrap();
        assert_eq!(minors["0000:00:03.0"], 0);
        assert_eq!(minors["0000:00:05.0"], 1);
    }
}

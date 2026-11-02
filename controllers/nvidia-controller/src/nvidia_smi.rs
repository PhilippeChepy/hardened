//! NVIDIA's `nvidia-smi`, of the driver root, which partitions the GPUs (MIG): a glibc program,
//! run by the loader of the glibc the driver root holds for it (the host has no
//! `/lib64/ld-linux-x86-64.so.2`), which finds NVML (`libnvidia-ml.so.1`) there too.

use std::path::Path;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;

use anyhow::Context as _;
use anyhow::bail;
use nvidia_controller::nvidia::MigMode;

/// `nvidia-smi` in a driver root.
#[derive(Debug, Clone)]
pub struct NvidiaSmi {
    root: PathBuf,
}

/// A GPU's MIG mode, as `nvidia-smi` reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GpuMigMode {
    /// Its PCI address, as sysfs writes it (`0000:17:00.0`).
    pub address: String,
    pub mode: MigMode,
}

impl NvidiaSmi {
    /// The one of the driver root `root` (`/usr/lib/nvidia/<version>/root`).
    #[must_use]
    pub fn new(root: PathBuf) -> Self {
        Self { root }
    }

    /// The MIG mode of each GPU.
    ///
    /// # Errors
    ///
    /// When `nvidia-smi` fails, or its output is not understood.
    pub fn mig_modes(&self) -> anyhow::Result<Vec<GpuMigMode>> {
        let output = self.run(&[
            "--query-gpu=pci.bus_id,mig.mode.current,mig.mode.pending",
            "--format=csv,noheader",
        ])?;
        parse_mig_modes(&output)
    }

    /// Enables or disables MIG mode on the GPU at `address`; an Ampere GPU applies it once reset.
    ///
    /// # Errors
    ///
    /// When `nvidia-smi` fails.
    pub fn set_mig_mode(&self, address: &str, enabled: bool) -> anyhow::Result<()> {
        let mode = if enabled { "1" } else { "0" };
        self.run(&["-i", address, "-mig", mode]).map(drop)
    }

    /// Creates, on the GPU at `address`, a GPU instance of each of `profiles`, each with its
    /// default compute instance.
    ///
    /// # Errors
    ///
    /// When `nvidia-smi` fails: a profile the GPU does not have, or not enough room left.
    pub fn create_instances(&self, address: &str, profiles: &[String]) -> anyhow::Result<()> {
        let profiles = profiles.join(",");
        self.run(&["mig", "-i", address, "-cgi", &profiles, "-C"])
            .map(drop)
    }

    /// Destroys the compute and GPU instances of the GPU at `address`.
    ///
    /// # Errors
    ///
    /// When `nvidia-smi` fails: there are none, or they are in use.
    pub fn destroy_instances(&self, address: &str) -> anyhow::Result<()> {
        self.run(&["mig", "-i", address, "-dci"])?;
        self.run(&["mig", "-i", address, "-dgi"]).map(drop)
    }

    /// Runs `nvidia-smi` with `args`, without environment; returns its output.
    fn run(&self, args: &[&str]) -> anyhow::Result<String> {
        let lib64 = self.root.join("usr/lib64");
        let libraries = [lib64.as_path(), &self.root.join("usr/lib/x86_64-linux-gnu")]
            .map(Path::to_string_lossy)
            .join(":");
        let output = Command::new(lib64.join("ld-linux-x86-64.so.2"))
            .arg("--library-path")
            .arg(libraries)
            .arg(self.root.join("usr/bin/nvidia-smi"))
            .args(args)
            .env_clear()
            .stdin(Stdio::null())
            .output()
            .context("running nvidia-smi")?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if !output.status.success() {
            // nvidia-smi writes its errors on stdout.
            let stderr = String::from_utf8_lossy(&output.stderr);
            let message = [stdout.trim(), stderr.trim()].join(" ");
            bail!(
                "nvidia-smi {}: {} ({})",
                args.join(" "),
                message.trim(),
                output.status
            );
        }
        Ok(stdout)
    }
}

/// The modes of `--query-gpu=pci.bus_id,mig.mode.current,mig.mode.pending` in CSV.
fn parse_mig_modes(output: &str) -> anyhow::Result<Vec<GpuMigMode>> {
    let mut modes = Vec::new();
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<&str> = line.split(',').map(str::trim).collect();
        let [bus_id, current, pending] = fields.as_slice() else {
            bail!("nvidia-smi: unexpected line {line:?}");
        };
        let mode = match (*current, *pending) {
            ("[N/A]", _) => MigMode::Unsupported,
            (current, pending) if current != pending => MigMode::Pending,
            ("Enabled", _) => MigMode::Enabled,
            ("Disabled", _) => MigMode::Disabled,
            _ => bail!("nvidia-smi: unexpected MIG mode in {line:?}"),
        };
        modes.push(GpuMigMode {
            address: pci_address(bus_id).with_context(|| format!("nvidia-smi: {line:?}"))?,
            mode,
        });
    }
    Ok(modes)
}

/// The sysfs address of the bus ID of `nvidia-smi`, whose domain has 8 digits
/// (`00000000:17:00.0`).
fn pci_address(bus_id: &str) -> anyhow::Result<String> {
    let Some((domain, rest)) = bus_id.split_once(':') else {
        bail!("invalid PCI bus ID {bus_id:?}");
    };
    let domain = u32::from_str_radix(domain, 16).context("invalid PCI domain")?;
    Ok(format!("{domain:04x}:{}", rest.to_ascii_lowercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mig_modes_by_sysfs_address() {
        let output = "00000000:10:1C.0, Enabled, Enabled\n00000000:20:1C.0, Disabled, Enabled\n\
                      00000000:30:1C.0, Disabled, Disabled\n00000000:00:1E.0, [N/A], [N/A]\n";
        let modes = parse_mig_modes(output).unwrap();
        let mode = |address: &str| {
            modes
                .iter()
                .find(|gpu| gpu.address == address)
                .map(|gpu| gpu.mode)
        };
        assert_eq!(mode("0000:10:1c.0"), Some(MigMode::Enabled));
        assert_eq!(mode("0000:20:1c.0"), Some(MigMode::Pending));
        assert_eq!(mode("0000:30:1c.0"), Some(MigMode::Disabled));
        assert_eq!(mode("0000:00:1e.0"), Some(MigMode::Unsupported));
        assert!(parse_mig_modes("00000000:10:1C.0, Enabled\n").is_err());
    }
}

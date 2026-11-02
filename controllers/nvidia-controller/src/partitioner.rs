//! MIG partitioning: each GPU's MIG mode, then its instances, with `nvidia-smi`. The GPU keeps
//! its instances until it is reset (at reboot): those it was given are recorded, by PCI address,
//! in the runtime directory, so that a restarted nvidia-controller neither recreates nor forgets
//! them. Ampere GPUs change their MIG mode once reset: at the next boot, machine-controller
//! rebooting the machine as Bottlerocket does.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::PathBuf;

use anyhow::Context as _;
use controllers_helpers::atomic_file;
use nvidia_controller::Mig;
use nvidia_controller::nvidia;
use nvidia_controller::nvidia::MigMode;

use crate::mig_layout;
use crate::nvidia_smi::GpuMigMode;
use crate::nvidia_smi::NvidiaSmi;

/// Partitions GPUs, keeping its records in a directory.
#[derive(Debug, Clone)]
pub struct Partitioner {
    smi: NvidiaSmi,
    records: PathBuf,
}

/// What partitioning did.
#[derive(Debug, Default)]
pub struct Outcome {
    /// A GPU's MIG mode changes once reset.
    pub reboot_required: bool,
    /// What failed, GPU by GPU.
    pub errors: Vec<String>,
}

impl Partitioner {
    /// With `smi`, recording in `records` (`/run/nvidia-controller/mig`).
    #[must_use]
    pub fn new(smi: NvidiaSmi, records: PathBuf) -> Self {
        Self { smi, records }
    }

    /// Partitions `gpus` for `mig` (whole GPUs without it), then updates their MIG modes and
    /// instances. A GPU partitioned already as wanted is left as it is.
    pub fn apply(&self, mig: Option<&Mig>, gpus: &mut [nvidia::Gpu]) -> Outcome {
        let mut outcome = Outcome::default();
        match self.smi.mig_modes() {
            Ok(modes) => set_modes(gpus, &modes),
            Err(e) => {
                outcome.errors.push(format!("{e:#}"));
                return outcome;
            }
        }
        for gpu in gpus.iter() {
            let applied = match mig {
                Some(mig) => self.partition(gpu, mig),
                None => self.join(gpu),
            };
            match applied {
                Ok(reboot_required) => outcome.reboot_required |= reboot_required,
                Err(e) => {
                    tracing::error!(gpu = gpu.pci_address, error = format!("{e:#}"), "MIG");
                    let error = format!("{}: {e:#}", gpu.pci_address);
                    outcome.errors.push(error);
                }
            }
        }
        self.refresh(gpus);
        outcome
    }

    /// Updates the MIG modes and instances of `gpus`, logging what cannot be read.
    pub fn refresh(&self, gpus: &mut [nvidia::Gpu]) {
        match self.smi.mig_modes() {
            Ok(modes) => set_modes(gpus, &modes),
            Err(e) => tracing::warn!(error = format!("{e:#}"), "cannot read the MIG modes"),
        }
        for gpu in gpus {
            gpu.mig_instances = match self.recorded(&gpu.pci_address) {
                Ok(instances) => instances.unwrap_or_default(),
                Err(e) => {
                    tracing::warn!(gpu = gpu.pci_address, error = %e, "cannot read its record");
                    Vec::new()
                }
            };
        }
    }

    /// Enables MIG mode on `gpu` and gives it the instances of `mig`; returns whether a reboot
    /// is required first.
    fn partition(&self, gpu: &nvidia::Gpu, mig: &Mig) -> anyhow::Result<bool> {
        let address = gpu.pci_address.as_str();
        match gpu.mig_mode() {
            MigMode::Unsupported => {
                tracing::warn!(gpu = address, "no MIG on this GPU: it stays whole");
                return Ok(false);
            }
            MigMode::Unspecified => anyhow::bail!("nvidia-smi does not report this GPU"),
            MigMode::Enabled => {}
            MigMode::Disabled | MigMode::Pending => {
                self.smi.set_mig_mode(address, true)?;
                tracing::info!(gpu = address, "MIG mode enabled");
                if self.mode(address)? != MigMode::Enabled {
                    tracing::info!(gpu = address, "MIG mode enabled once the GPU is reset");
                    return Ok(true);
                }
            }
        }
        let layouts = mig_layout::layouts(gpu.device_id, mig).map_err(anyhow::Error::msg)?;
        let recorded = self.recorded(address)?;
        if recorded
            .as_ref()
            .is_some_and(|recorded| layouts.contains(recorded))
        {
            return Ok(false);
        }
        self.destroy(address, recorded.is_some())?;
        let mut tried = Vec::new();
        for layout in layouts {
            match self.smi.create_instances(address, &layout) {
                Ok(()) => {
                    self.record(address, Some(&layout))?;
                    tracing::info!(gpu = address, instances = layout.join(","), "MIG instances");
                    return Ok(false);
                }
                Err(e) => tried.push(format!("{e:#}")),
            }
        }
        if tried.is_empty() {
            anyhow::bail!(
                "no profile of mig.profile for this GPU (PCI device {:#06x})",
                gpu.device_id
            );
        }
        anyhow::bail!("{}", tried.join("; "))
    }

    /// Disables MIG mode on `gpu`, a whole GPU again; returns whether a reboot is required first.
    fn join(&self, gpu: &nvidia::Gpu) -> anyhow::Result<bool> {
        let address = gpu.pci_address.as_str();
        match gpu.mig_mode() {
            MigMode::Unsupported | MigMode::Disabled | MigMode::Unspecified => return Ok(false),
            MigMode::Enabled | MigMode::Pending => {}
        }
        self.destroy(address, false)?;
        self.smi.set_mig_mode(address, false)?;
        tracing::info!(gpu = address, "MIG mode disabled");
        Ok(self.mode(address)? != MigMode::Disabled)
    }

    /// Destroys the instances of the GPU at `address`, and their record. Without a record,
    /// there may be none: failing is not an error then.
    fn destroy(&self, address: &str, recorded: bool) -> anyhow::Result<()> {
        match self.smi.destroy_instances(address) {
            Ok(()) => tracing::info!(gpu = address, "MIG instances destroyed"),
            Err(e) if recorded => return Err(e),
            Err(_) => {}
        }
        self.record(address, None)
    }

    /// The MIG mode of the GPU at `address` now.
    fn mode(&self, address: &str) -> anyhow::Result<MigMode> {
        let modes = self.smi.mig_modes()?;
        Ok((modes.iter())
            .find(|gpu| gpu.address == address)
            .map_or(MigMode::Unspecified, |gpu| gpu.mode))
    }

    /// The profiles of the instances recorded for the GPU at `address`.
    fn recorded(&self, address: &str) -> io::Result<Option<Vec<String>>> {
        match fs::read_to_string(self.records.join(address)) {
            Ok(text) => Ok(Some(text.split_whitespace().map(str::to_owned).collect())),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Records `instances` for the GPU at `address`, or removes its record.
    fn record(&self, address: &str, instances: Option<&[String]>) -> anyhow::Result<()> {
        let path = self.records.join(address);
        let written = match instances {
            Some(instances) => fs::create_dir_all(&self.records).and_then(|()| {
                atomic_file::write(
                    &path,
                    format!("{}\n", instances.join(" ")).as_bytes(),
                    0o644,
                )
            }),
            None => match fs::remove_file(&path) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
                removed => removed,
            },
        };
        written.with_context(|| path.display().to_string())
    }
}

/// Sets the MIG modes of `gpus` from `modes`; those `nvidia-smi` does not report have none.
fn set_modes(gpus: &mut [nvidia::Gpu], modes: &[GpuMigMode]) {
    let modes: BTreeMap<&str, MigMode> = (modes.iter())
        .map(|gpu| (gpu.address.as_str(), gpu.mode))
        .collect();
    for gpu in gpus {
        let mode = modes.get(gpu.pci_address.as_str()).copied();
        gpu.set_mig_mode(mode.unwrap_or(MigMode::Unspecified));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records_by_address() {
        let dir = tempfile::tempdir().unwrap();
        let partitioner = Partitioner::new(
            NvidiaSmi::new(PathBuf::from("/nonexistent")),
            dir.path().join("mig"),
        );
        let address = "0000:10:1c.0";
        assert_eq!(partitioner.recorded(address).unwrap(), None);
        let layout = vec!["2g.10gb".to_owned(); 3];
        partitioner.record(address, Some(&layout)).unwrap();
        assert_eq!(partitioner.recorded(address).unwrap(), Some(layout));
        partitioner.record(address, None).unwrap();
        partitioner.record(address, None).unwrap();
        assert_eq!(partitioner.recorded(address).unwrap(), None);
    }

    #[test]
    fn without_nvidia_smi_nothing_is_done() {
        let dir = tempfile::tempdir().unwrap();
        let partitioner = Partitioner::new(
            NvidiaSmi::new(dir.path().to_owned()),
            dir.path().join("mig"),
        );
        let mut gpus = vec![nvidia::Gpu {
            pci_address: "0000:10:1c.0".to_owned(),
            device_id: 0x20b0,
            ..nvidia::Gpu::default()
        }];
        let outcome = partitioner.apply(Some(&Mig::default()), &mut gpus);
        assert!(!outcome.reboot_required);
        assert_eq!(outcome.errors.len(), 1, "{:?}", outcome.errors);
        assert_eq!(gpus[0].mig_mode(), MigMode::Unspecified);
    }
}

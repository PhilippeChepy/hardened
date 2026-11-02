//! What nvidia-controller does at boot: when there are NVIDIA GPUs, loads the driver and makes
//! its device nodes. Nothing here fails: what cannot be done is logged, and in the state.

use std::path::Path;

use nvidia_controller::nvidia;

use crate::device_nodes;
use crate::driver::Driver;
use crate::pci_gpu;

/// Sets the GPUs up with `driver`: the state the API serves.
#[must_use]
pub fn run(driver: &Driver) -> nvidia::State {
    let mut state = nvidia::State {
        driver_version: driver.version(),
        ..nvidia::State::default()
    };
    let gpus = match pci_gpu::scan(Path::new("/sys/bus/pci/devices")) {
        Ok(gpus) => gpus,
        Err(e) => {
            tracing::error!(error = %e, "cannot list the PCI devices");
            state.error = Some(format!("listing the PCI devices: {e}"));
            return state;
        }
    };
    state.gpus = (gpus.iter())
        .map(|gpu| nvidia::Gpu {
            pci_address: gpu.address.clone(),
            device_id: gpu.device_id,
            ..nvidia::Gpu::default()
        })
        .collect();
    if gpus.is_empty() {
        tracing::info!("no NVIDIA GPU: the driver is not loaded");
        return state;
    }
    let made = driver
        .load()
        .and_then(|()| device_nodes::make(Path::new("/dev"), Path::new("/proc")));
    match made {
        Ok(minors) => {
            for gpu in &mut state.gpus {
                gpu.minor = minors.get(&gpu.pci_address).copied();
            }
            state.ready = true;
            tracing::info!(
                gpus = state.gpus.len(),
                version = state.driver_version,
                "driver ready"
            );
        }
        Err(e) => {
            tracing::error!(error = format!("{e:#}"), "cannot set the NVIDIA GPUs up");
            state.error = Some(format!("{e:#}"));
        }
    }
    state
}

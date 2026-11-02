//! NVIDIA's Kubernetes plugins, on the NVIDIA variant's nodes: once nvidia-controller loaded the
//! driver for the node's GPUs and partitioned them (MIG), and kubelet runs, the device plugin and
//! the DRA kubelet plugin (each as `settings` enables it) are workloads next to user-data's.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::Context as _;
use controllers_helpers::WorkloadName;
use controllers_helpers::atomic_file;
use libserviced::api::serviced_client::ServicedClient;
use machine_controller::Settings;
use nvidia_controller::DevicePluginSettings;
use nvidia_controller::nvidia::nvidia_controller_client::NvidiaControllerClient;
use nvidia_controller::plugin_workloads;
use tracing::error;
use tracing::info;
use workload_controller::ContainerSettings;
use workload_controller::ImageWorkload;

use crate::controllers::Controllers;

/// Partitions the GPUs as `settings` says, then returns the plugins' workloads on the node
/// `node_name`; none without nvidia-controller (another variant), kubelet or a GPU the driver is
/// ready for. When a GPU's MIG mode changes only once it is reset, reboots the machine (as
/// Bottlerocket does), and returns none.
pub async fn workloads(
    controllers: &Controllers,
    settings: &Settings,
    node_name: &str,
) -> BTreeMap<WorkloadName, ContainerSettings> {
    let mut workloads = BTreeMap::new();
    if !controllers.nvidia.exists() {
        return workloads;
    }
    let mut nvidia = NvidiaControllerClient::new(controllers.nvidia.channel());
    let device_plugin = &settings.kubelet_device_plugins.nvidia;
    let partitioned = nvidia.configure(device_plugin.partitioning()).await;
    if let Err(status) = &partitioned {
        error!(
            error = status.message(),
            "the GPUs are not partitioned as configured"
        );
    }
    let state = match nvidia.get_state(()).await {
        Ok(state) => state.into_inner(),
        Err(status) => {
            error!(
                error = status.message(),
                "cannot read nvidia-controller's state"
            );
            return workloads;
        }
    };
    if state.reboot_required {
        info!("rebooting: a GPU's MIG mode changes once it is reset");
        if let Err(status) = ServicedClient::new(controllers.serviced.channel())
            .reboot(())
            .await
        {
            error!(error = status.message(), "cannot reboot");
        }
        return workloads;
    }
    if settings.kubernetes.is_none() {
        return workloads;
    }
    if !state.ready {
        info!(
            gpus = state.gpus.len(),
            "the NVIDIA driver is not ready: no GPU plugin"
        );
        return workloads;
    }
    let version = state.driver_version.as_str();
    if device_plugin.enabled && partitioned.is_err() {
        error!("the NVIDIA device plugin does not run: the GPUs are not partitioned as configured");
    } else if device_plugin.enabled {
        let declared = write_device_plugin_config(device_plugin)
            .and_then(|()| Ok(plugin_workloads::device_plugin(device_plugin, version)?));
        add(&mut workloads, declared);
    }
    if settings.hardened.nvidia_dra.enabled {
        add(
            &mut workloads,
            plugin_workloads::dra_kubelet_plugin(node_name, version).map_err(Into::into),
        );
    }
    workloads
}

fn add(
    workloads: &mut BTreeMap<WorkloadName, ContainerSettings>,
    declared: anyhow::Result<(WorkloadName, ImageWorkload)>,
) {
    match declared {
        Ok((name, workload)) => {
            info!(workload = %name, "NVIDIA plugin declared");
            workloads.insert(
                name,
                ContainerSettings {
                    enabled: true,
                    workload,
                },
            );
        }
        Err(e) => error!(error = format!("{e:#}"), "cannot declare an NVIDIA plugin"),
    }
}

/// Writes the device plugin's time-slicing configuration, when it shares the GPUs.
fn write_device_plugin_config(settings: &DevicePluginSettings) -> anyhow::Result<()> {
    let Some(config) = plugin_workloads::time_slicing_config(settings) else {
        return Ok(());
    };
    let dir = Path::new(plugin_workloads::DEVICE_PLUGIN_CONFIG_DIR);
    fs::create_dir_all(dir).with_context(|| dir.display().to_string())?;
    let path = dir.join("config.yaml");
    atomic_file::write(&path, config.as_bytes(), 0o644).with_context(|| path.display().to_string())
}

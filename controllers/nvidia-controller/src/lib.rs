//! nvidia-controller's API (`hardened.nvidia.v1`, on [`SOCKET`]): the NVIDIA GPUs of the machine,
//! for which it loads NVIDIA's open kernel modules and makes the device nodes at boot, and which it
//! partitions (MIG) as configured ([`DevicePluginSettings::partitioning`]). And the
//! settings of NVIDIA's Kubernetes plugins ([`DevicePluginSettings`], [`DraSettings`]), and their
//! workloads, which machine-controller declares on a node with GPUs ([`plugin_workloads`]).

#![warn(missing_docs)]

mod device_plugin_settings;
mod dra_settings;
pub mod plugin_workloads;
mod settings_message;
mod socket;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use device_plugin_settings::{
    DeviceIdStrategy, DeviceListStrategy, DevicePartitioningStrategy, DevicePluginSettings,
    DeviceSharingStrategy, GpuModel, Mig, MigProfile, Mps, TimeSlicing,
};
pub use dra_settings::DraSettings;
pub use generated::hardened::nvidia::v1 as nvidia;
pub use socket::SOCKET;

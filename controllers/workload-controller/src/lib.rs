//! workload-controller's APIs, on [`SOCKET`]: its configuration, the workloads of user-data
//! (`hardened.workload.v1`), and the API's workloads (`hardened.workloads.v1`); with the model
//! both declare workloads with ([`ImageWorkload`]).

#![warn(missing_docs)]

mod container_path;
mod container_settings;
mod declared_workload;
mod image_ref;
mod image_workload;
mod socket;
mod var_path;
mod workload_spec;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use container_path::ContainerPath;
pub use container_settings::ContainerSettings;
pub use generated::hardened::workload::v1 as workload;
pub use generated::hardened::workloads::v1 as workloads;
pub use image_ref::ImageRef;
pub use image_workload::{EnvName, EnvValue, ImageWorkload, MountSettings, RestartPolicy};
pub use socket::SOCKET;
pub use var_path::VarPath;

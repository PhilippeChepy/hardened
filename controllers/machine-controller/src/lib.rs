//! The machine's API (`hardened.machine.v1`, and `hardened.services.v1`), which machine-controller serves on its socket and
//! machine-apiproxy over mutual TLS, and the settings machine-controller reads from user-data
//! ([`UserData`], [`Settings`]).
//!
//! machine-controller pushes each controller its part of the settings, a type of the
//! controller's crate, as that controller's message; it applies the kernel's and the container
//! registries' itself.

#![warn(missing_docs)]

mod module_name;
mod settings;
mod sysctl_key;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use generated::hardened::machine::v1 as machine;
pub use generated::hardened::services::v1 as services;
pub use module_name::ModuleName;
pub use settings::{
    Auth, Endpoint, Error, ModuleLoad, NtpSettings, Registry, RegistrySettings, Settings, UserData,
};
pub use sysctl_key::SysctlKey;

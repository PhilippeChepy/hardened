//! storage-controller's API (`hardened.storage.v1`, on [`SOCKET`]): how the state partition is
//! set up ([`StorageSettings`]), and what backs `/var`.

#![warn(missing_docs)]

mod socket;
mod storage_configuration;
mod storage_settings;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use generated::hardened::storage::v1 as storage;
pub use socket::SOCKET;
pub use storage_settings::{Encryption, StorageSettings};

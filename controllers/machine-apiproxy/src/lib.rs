//! machine-apiproxy's API (`hardened.apiproxy.v1`, on [`SOCKET`]): the address and TLS identity
//! it serves the machine's API with ([`ApiConfig`]), and the [`Role`]s it authorizes its clients
//! with.

#![warn(missing_docs)]

mod api_config;
mod apiproxy_configuration;
mod role;
mod socket;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use api_config::ApiConfig;
pub use generated::hardened::apiproxy::v1 as apiproxy;
pub use role::Role;
pub use socket::SOCKET;

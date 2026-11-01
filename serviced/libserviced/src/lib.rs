//! What a service of hardened needs from serviced, as libsystemd is to systemd:
//!
//! - [`definition`]: service files: their format, layers, merging and validation.
//! - [`api`] and [`connect`]: serviced's API.
//! - [`notify`]: telling serviced the service is ready.
//! - [`activation`]: the sockets serviced passes the service, with their allow-lists.
//! - [`authorization`]: serving a gRPC API on such a socket to the services it allows, which
//!   serviced's `IdentifyProcess` names from each connection's pid.
//! - [`client`]: what clients of serviced's API share.
//! - `testing` (feature `testing`): a fake serviced for their tests.

#![warn(missing_docs)]

pub mod activation;
mod atomic_file;
pub mod authorization;
pub mod client;
mod connect;
pub mod definition;
pub mod notify;
#[cfg(feature = "testing")]
pub mod testing;
mod unix_channel;

/// The code prost and tonic generate from `proto/`, whose comments document what they cover.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/serviced.rs"));
}

/// serviced's API (`hardened.serviced.v1`).
pub use generated::hardened::serviced::v1 as api;

/// serviced's socket.
pub const SOCKET: &str = "/run/serviced/serviced.sock";

pub use connect::{connect, connect_to};

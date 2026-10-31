//! time-controller's API (`hardened.time.v1`, on [`SOCKET`]): what it synchronizes the clock with
//! ([`TimeConfig`]: the hypervisor's PTP clock or time servers), and the clock's status.

#![warn(missing_docs)]

mod socket;
mod time_config;
mod time_configuration;
mod time_server;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use generated::hardened::time::v1 as time;
pub use socket::SOCKET;
pub use time_config::{TimeConfig, TimeOrigin, TimeSource};
pub use time_server::TimeServer;

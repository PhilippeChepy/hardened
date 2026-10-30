//! network-controller's API (`hardened.network.v1`, on [`SOCKET`]): the resolver configuration
//! of `settings.dns` ([`DnsSettings`]), and what DHCP offered.

#![warn(missing_docs)]

mod dns_settings;
mod network_configuration;
mod socket;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use dns_settings::DnsSettings;
pub use generated::hardened::network::v1 as network;
pub use socket::SOCKET;

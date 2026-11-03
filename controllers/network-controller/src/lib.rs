//! network-controller's API (`hardened.network.v1`, on [`SOCKET`]): the resolver configuration
//! of `settings.dns` ([`DnsSettings`]), what DHCP offered, and each physical Ethernet interface's
//! configuration ([`InterfaceSettings`]).

#![warn(missing_docs)]

mod dns_settings;
mod interface_configuration;
mod interface_name;
mod interface_settings;
mod ipv4_address;
mod mtu;
mod network_configuration;
mod socket;
mod static_ipv4;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use dns_settings::DnsSettings;
pub use generated::hardened::network::v1 as network;
pub use interface_name::InterfaceName;
pub use interface_settings::InterfaceSettings;
pub use interface_settings::InvalidInterfaceDns;
pub use interface_settings::Ipv4Method;
pub use ipv4_address::Ipv4Address;
pub use mtu::InvalidMtu;
pub use mtu::Mtu;
pub use socket::SOCKET;
pub use static_ipv4::InvalidStaticIpv4;
pub use static_ipv4::StaticIpv4;

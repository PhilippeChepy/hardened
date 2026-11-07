//! firewall-controller's API (`hardened.firewall.v1`, on [`SOCKET`]) and what it is built on:
//! the configuration ([`FirewallConfig`]: on or off, and what it lets through), the nftables
//! ruleset it comes to ([`Ruleset`], in nft's syntax by [`ruleset::text`]), nf_tables' netlink
//! API that applies it ([`nftables`]), and what the kernel's log says was blocked
//! ([`drop_log`]).

#![warn(missing_docs)]

mod configuration;
pub mod drop_log;
pub mod nftables;
mod policy;
mod ports;
pub mod ruleset;
mod service;
mod socket;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use generated::hardened::firewall::v1 as firewall;
pub use policy::{
    Allowed, AllowedList, FirewallConfig, Inbound, InvalidAllowed, InvalidAllowedList, Outbound,
};
pub use ports::{InvalidPorts, Port, Ports, Protocol};
pub use ruleset::Ruleset;
pub use service::{SERVICES, Service, ServiceInfo, UnknownService};
pub use socket::SOCKET;

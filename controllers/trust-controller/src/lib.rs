//! trust-controller's APIs, on [`SOCKET`]: sealing secrets to the booted image
//! (`hardened.trust.v1`), and the attestation evidence of the machine's API
//! (`hardened.attestation.v1`); and [`quote_verification`], for its verifiers.

#![warn(missing_docs)]

pub mod quote_verification;
mod socket;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use generated::hardened::attestation::v1 as attestation;
pub use generated::hardened::trust::v1 as trust;
pub use socket::SOCKET;

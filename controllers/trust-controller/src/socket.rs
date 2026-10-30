//! Where trust-controller's API listens.

/// trust-controller's API (sealing, and `hardened.attestation.v1.Attestation`). serviced creates
/// the socket (the service's `[[sockets]]`) and binds it into the sandboxes of the services it
/// allows.
pub const SOCKET: &str = "/run/trust-controller/api.sock";

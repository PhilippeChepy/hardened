//! Where machine-apiproxy's API listens.

/// machine-apiproxy's API (its configuration). serviced creates the socket (the service's
/// `[[sockets]]`) and binds it into the sandboxes of the services it allows.
pub const SOCKET: &str = "/run/machine-apiproxy/api.sock";

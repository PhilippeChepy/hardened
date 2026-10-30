//! Where time-controller's API listens.

/// time-controller's API. serviced creates the socket (the service's `[[sockets]]`) and binds it
/// into the sandboxes of the services it allows.
pub const SOCKET: &str = "/run/time-controller/api.sock";

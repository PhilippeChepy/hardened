//! Where workload-console's API listens.

/// workload-console's API (`hardened.console.v1.Console`). serviced creates the socket (the
/// service's `[[sockets]]`) and binds it into the sandboxes of the services it allows.
pub const SOCKET: &str = "/run/workload-console/api.sock";

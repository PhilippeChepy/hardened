//! Where workload-controller's API listens.

/// workload-controller's API (configuration, and `hardened.workloads.v1.Workloads`). serviced
/// creates the socket (the service's `[[sockets]]`) and binds it into the sandboxes of the
/// services it allows.
pub const SOCKET: &str = "/run/workload-controller/api.sock";

//! Kernel parameters: Kubernetes' defaults, then the user's overrides. serviced sets the
//! hardened defaults before any service starts.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use machine_controller::SysctlKey;
use tracing::warn;

/// Applied when kubelet runs, before user-data overrides: pod traffic is routed through the host.
/// IPv6 forwarding is left to user-data: it would turn off the router advertisements SLAAC
/// configures addresses from.
pub fn apply_kubernetes_defaults() {
    set("net.ipv4.ip_forward", "1");
}

/// Sets the sysctls of user-data; one that cannot be set is logged and skipped.
pub fn apply(overrides: &BTreeMap<SysctlKey, String>) {
    for (key, value) in overrides {
        set(key.as_str(), value);
    }
}

/// `key` is trusted: a [`SysctlKey`] cannot escape `/proc/sys`.
fn set(key: &str, value: &str) {
    let path = Path::new("/proc/sys").join(key.replace('.', "/"));
    if let Err(e) = fs::write(path, value) {
        warn!(%key, value, error = %e, "cannot set sysctl");
    }
}

//! Kernel parameters: hardened defaults, then the user's overrides.

use std::collections::BTreeMap;

use tracing::warn;

use crate::types::SysctlKey;

/// Applied at every boot, before user-data overrides.
const DEFAULTS: &[(&str, &str)] = &[
    ("kernel.kptr_restrict", "2"),
    ("kernel.dmesg_restrict", "1"),
    ("kernel.perf_event_paranoid", "3"),
    ("kernel.yama.ptrace_scope", "1"),
    ("kernel.unprivileged_bpf_disabled", "1"),
    ("kernel.panic", "10"),
    ("kernel.panic_on_oops", "1"),
    ("fs.protected_hardlinks", "1"),
    ("fs.protected_symlinks", "1"),
    ("fs.protected_fifos", "2"),
    ("fs.protected_regular", "2"),
    ("fs.suid_dumpable", "0"),
    ("fs.inotify.max_user_instances", "8192"),
    ("fs.inotify.max_user_watches", "524288"),
    ("net.ipv4.tcp_syncookies", "1"),
    ("net.ipv4.conf.all.rp_filter", "1"),
    ("net.ipv4.conf.default.rp_filter", "1"),
    ("net.ipv4.conf.all.accept_redirects", "0"),
    ("net.ipv4.conf.default.accept_redirects", "0"),
    ("net.ipv4.conf.all.send_redirects", "0"),
    ("net.ipv4.conf.all.accept_source_route", "0"),
    ("net.ipv6.conf.all.accept_redirects", "0"),
    ("net.ipv6.conf.default.accept_redirects", "0"),
];

/// Applied when kubelet runs, before user-data overrides: pod traffic is routed through the
/// host. IPv6 forwarding is left to user-data: it would turn off the router advertisements SLAAC
/// configures addresses from.
const KUBERNETES: &[(&str, &str)] = &[("net.ipv4.ip_forward", "1")];

pub fn apply_defaults() {
    apply_static(DEFAULTS);
}

pub fn apply_kubernetes_defaults() {
    apply_static(KUBERNETES);
}

fn apply_static(values: &[(&str, &str)]) {
    for (key, value) in values {
        match key.parse::<SysctlKey>() {
            Ok(key) => set(&key, value),
            Err(e) => warn!("{e}"),
        }
    }
}

pub fn apply(overrides: &BTreeMap<SysctlKey, String>) {
    for (key, value) in overrides {
        set(key, value);
    }
}

fn set(key: &SysctlKey, value: &str) {
    if let Err(e) = std::fs::write(key.proc_path(), value) {
        warn!(%key, value, "cannot set sysctl: {e}");
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn defaults_are_valid_keys() {
        for (key, _) in super::DEFAULTS.iter().chain(super::KUBERNETES) {
            assert!(key.parse::<super::SysctlKey>().is_ok(), "{key}");
        }
    }
}

//! Kernel settings made at boot, before any service starts: LoadPin's pin, and the hardened sysctls
//! (services may change some later, from user-data).

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use tracing::{info, warn};

/// A regular file of the root filesystem, never a module.
const PIN_FILE: &str = "/usr/lib/os-release";

/// The hardened sysctls: key, value.
const SYSCTLS: &[(&str, &str)] = &[
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

/// Pins LoadPin to the root filesystem before anything else can load a kernel file: otherwise a
/// privileged workload loading the first module from `/var` would pin that filesystem instead.
/// LoadPin pins when it checks the file, before the kernel reads it as a module, so a regular
/// file of the root does (the kernel then rejects it as unsigned).
pub fn pin() {
    let result = rustix::fs::open(PIN_FILE, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .and_then(|file| rustix::system::finit_module(&file, c"", 0));
    match result {
        Err(Errno::KEYREJECTED | Errno::NOEXEC | Errno::INVAL) => {
            info!("kernel files pinned to the root filesystem")
        }
        Ok(()) => warn!("{PIN_FILE} loaded as a kernel module"),
        Err(e) => warn!("cannot pin kernel files to the root filesystem: {e}"),
    }
}

/// Sets the hardened sysctls; those the kernel lacks are warned about.
pub fn apply_sysctls() {
    for (key, value) in SYSCTLS {
        if let Err(e) = std::fs::write(format!("/proc/sys/{}", key.replace('.', "/")), value) {
            warn!(key, value, "cannot set sysctl: {e}");
        }
    }
}

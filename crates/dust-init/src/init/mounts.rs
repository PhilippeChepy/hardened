//! Early mounts. The kernel mounted the verity root read-only and devtmpfs on `/dev`.

use std::path::Path;

use anyhow::Context;
use rustix::fs::Mode;
use rustix::mount::{MountFlags, mount};

struct Mount {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    flags: MountFlags,
    data: &'static std::ffi::CStr,
}

const NOSUID_NODEV_NOEXEC: MountFlags = MountFlags::NOSUID.union(MountFlags::NODEV).union(MountFlags::NOEXEC);

const MOUNTS: &[Mount] = &[
    Mount {
        source: "proc",
        target: "/proc",
        fstype: "proc",
        flags: NOSUID_NODEV_NOEXEC,
        data: c"hidepid=invisible",
    },
    Mount {
        source: "sysfs",
        target: "/sys",
        fstype: "sysfs",
        flags: NOSUID_NODEV_NOEXEC,
        data: c"",
    },
    Mount {
        source: "devtmpfs",
        target: "/dev",
        fstype: "devtmpfs",
        flags: MountFlags::NOSUID,
        data: c"mode=0755",
    },
    Mount {
        source: "devpts",
        target: "/dev/pts",
        fstype: "devpts",
        flags: MountFlags::NOSUID.union(MountFlags::NOEXEC),
        data: c"mode=0620,ptmxmode=0666",
    },
    Mount {
        source: "tmpfs",
        target: "/dev/shm",
        fstype: "tmpfs",
        flags: NOSUID_NODEV_NOEXEC,
        data: c"mode=1777",
    },
    Mount {
        source: "tmpfs",
        target: "/run",
        fstype: "tmpfs",
        flags: MountFlags::NOSUID.union(MountFlags::NODEV),
        data: c"mode=0755",
    },
    Mount {
        source: "tmpfs",
        target: "/tmp",
        fstype: "tmpfs",
        flags: MountFlags::NOSUID.union(MountFlags::NODEV),
        data: c"mode=1777",
    },
    Mount {
        source: "cgroup2",
        target: "/sys/fs/cgroup",
        fstype: "cgroup2",
        flags: NOSUID_NODEV_NOEXEC,
        data: c"nsdelegate,memory_recursiveprot",
    },
    Mount {
        source: "securityfs",
        target: "/sys/kernel/security",
        fstype: "securityfs",
        flags: NOSUID_NODEV_NOEXEC,
        data: c"",
    },
    Mount {
        source: "bpf",
        target: "/sys/fs/bpf",
        fstype: "bpf",
        flags: NOSUID_NODEV_NOEXEC,
        data: c"mode=0700",
    },
];

/// Mounts the API filesystems and the tmpfs directories.
pub fn mount_early() -> anyhow::Result<()> {
    for m in MOUNTS {
        let target = Path::new(m.target);
        if !target.exists() {
            rustix::fs::mkdir(target, Mode::from_raw_mode(0o755)).with_context(|| format!("creating {}", m.target))?;
        }
        match mount(m.source, m.target, m.fstype, m.flags, m.data) {
            // devtmpfs is already mounted by the kernel (CONFIG_DEVTMPFS_MOUNT).
            Err(rustix::io::Errno::BUSY) => {}
            result => result.with_context(|| format!("mounting {} on {}", m.fstype, m.target))?,
        }
    }
    for dir in ["/run/hardened", "/run/dust", "/run/containerd"] {
        std::fs::create_dir_all(dir)?;
    }
    Ok(())
}

//! Early mounts and serviced's directories. The kernel mounted the verity root read-only and
//! devtmpfs on `/dev`.

use std::ffi::CStr;
use std::fs::DirBuilder;
use std::io;
use std::path::Path;

use anyhow::Context;
use libserviced::definition;
use rustix::fs::Mode;
use rustix::io::Errno;
use rustix::mount::MountFlags;
use rustix::process::{Gid, Uid};

/// A filesystem mounted at boot.
struct Mount {
    source: &'static str,
    target: &'static str,
    fstype: &'static str,
    flags: MountFlags,
    data: &'static CStr,
}

const NOSUID_NODEV_NOEXEC: MountFlags = MountFlags::NOSUID
    .union(MountFlags::NODEV)
    .union(MountFlags::NOEXEC);

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
    for entry in MOUNTS {
        let target = Path::new(entry.target);
        if !target.exists() {
            rustix::fs::mkdir(target, Mode::from_raw_mode(0o755))
                .with_context(|| format!("creating {}", entry.target))?;
        }
        match rustix::mount::mount(
            entry.source,
            entry.target,
            entry.fstype,
            entry.flags,
            entry.data,
        ) {
            // devtmpfs is already mounted by the kernel (CONFIG_DEVTMPFS_MOUNT).
            Err(Errno::BUSY) => {}
            result => {
                result.with_context(|| format!("mounting {} on {}", entry.fstype, entry.target))?
            }
        }
    }
    Ok(())
}

/// Creates serviced's directories in `/run`, root's and readable by everyone: this boot's services,
/// the logs before `/var` is mounted, and the services' notify sockets, in `/run/serviced` with
/// serviced's socket.
pub fn create_dirs() -> anyhow::Result<()> {
    let dirs = [
        definition::RUNTIME_DIR,
        definition::RUN_LOG_DIR,
        crate::notify_socket::DIR,
    ];
    for dir in dirs {
        create_dir(Path::new(dir), 0, 0o755)?;
    }
    Ok(())
}

/// Creates `dir` and its missing parents, root's (serviced's), mode 0755.
pub fn create_root_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;

    DirBuilder::new().recursive(true).mode(0o755).create(dir)
}

/// Creates `dir` and its parents; `dir` gets `owner` (as uid and gid) and `mode`. An existing
/// `dir` is left as it is: a workload's data directory keeps the owner its files need.
pub fn create_dir(dir: &Path, owner: u32, mode: u32) -> anyhow::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    rustix::fs::chown(dir, Some(Uid::from_raw(owner)), Some(Gid::from_raw(owner)))
        .with_context(|| format!("chown {}", dir.display()))?;
    rustix::fs::chmod(dir, Mode::from_raw_mode(mode))
        .with_context(|| format!("chmod {}", dir.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;

    #[test]
    fn leaves_existing_directories_as_they_are() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("data");
        fs::create_dir(&data).unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o700)).unwrap();
        create_dir(&data, 0, 0o755).unwrap();
        let mode = fs::metadata(&data).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o700);
    }
}

//! `storage-controller stop`: undoes the setup once the daemon is gone. serviced runs it last at
//! shutdown, once every other process is gone, so nothing holds `/var` any more. Unmounting it
//! cleanly (and closing the encrypted device) leaves a filesystem that needs no journal replay.
//!
//! It works without the daemon's API, from the mounts and the kept [`State`], which it marks as
//! no longer set up: a daemon restarted after a stop sets `/var` up again.

use std::cmp::Reverse;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use rustix::mount::UnmountFlags;
use tracing::{info, warn};

use crate::encryption;
use crate::encryption::MAPPED;
use crate::mount;
use crate::mount::Mount;
use crate::state;
use crate::state::State;

/// Unmounts everything at or under `/var`, deepest first (detaching what is still busy), then
/// closes the encrypted device if it is open, and records that `/var` is no longer set up.
pub fn run() -> anyhow::Result<()> {
    rustix::fs::sync();
    let mountinfo = fs::read_to_string(mount::MOUNTINFO).context(mount::MOUNTINFO)?;
    for target in unmount_order(&mountinfo, Path::new("/var")) {
        match rustix::mount::unmount(&target, UnmountFlags::empty()) {
            Ok(()) => info!(path = %target.display(), "unmounted"),
            Err(e) => {
                warn!(path = %target.display(), "cannot unmount: {e}; detaching it");
                if let Err(e) = rustix::mount::unmount(&target, UnmountFlags::DETACH) {
                    warn!(path = %target.display(), "cannot detach: {e}");
                }
            }
        }
    }
    let closed = if Path::new(MAPPED).exists() {
        encryption::close()
    } else {
        Ok(())
    };
    rustix::fs::sync();
    forget_backing(Path::new(state::PATH));
    closed
}

/// Records that `/var` is no longer set up, keeping its configuration.
fn forget_backing(path: &Path) {
    let forgotten = State::load(path).and_then(|state| match state {
        Some(State::SetUp { backing }) => State::Configured {
            encryption: backing.encryption(),
        }
        .save(path),
        _ => Ok(()),
    });
    if let Err(e) = forgotten {
        warn!("cannot record that /var is no longer set up: {e:#}");
    }
}

/// The mount points of `mountinfo` at or under `root`, deepest first (a path mounted several
/// times is listed as many times).
#[must_use]
fn unmount_order(mountinfo: &str, root: &Path) -> Vec<PathBuf> {
    let mut targets: Vec<PathBuf> = Mount::parse_all(mountinfo)
        .into_iter()
        .map(|mount| mount.target)
        .filter(|target| target.starts_with(root))
        .collect();
    // Stable: of mounts on the same path, the last mounted (on top) goes first.
    targets.reverse();
    targets.sort_by_key(|target| Reverse(target.components().count()));
    targets
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unmounts_var_deepest_first() {
        let mountinfo = "\
22 1 254:0 / / ro,relatime - erofs /dev/dm-0 ro
30 22 0:5 / /run rw - tmpfs tmpfs rw
40 22 253:1 / /var rw - ext4 /dev/mapper/state rw
41 40 0:50 / /var/lib/kubelet/pods/a\\040b/volumes rw - tmpfs tmpfs rw
42 40 0:51 / /var/lib/containerd/x rw - overlay overlay rw
43 22 0:52 / /variable rw - tmpfs tmpfs rw
44 40 0:53 / /var/lib/containerd/x rw - overlay overlay rw
";
        let order = unmount_order(mountinfo, Path::new("/var"));
        let order: Vec<&str> = order.iter().map(|p| p.to_str().unwrap()).collect();
        assert_eq!(
            order,
            [
                "/var/lib/kubelet/pods/a b/volumes",
                "/var/lib/containerd/x",
                "/var/lib/containerd/x",
                "/var",
            ]
        );
    }
}

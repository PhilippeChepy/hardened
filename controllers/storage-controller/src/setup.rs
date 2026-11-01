//! Setting `/var` up, once per boot.

use std::fs;
use std::fs::Permissions;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;
use libserviced::definition;
use libserviced::definition::Layer;
use rustix::process::Gid;
use rustix::process::Uid;
use storage_controller::Encryption;
use tokio::runtime::Handle;
use tracing::error;
use tracing::info;

use crate::backing::Backing;
use crate::encryption;
use crate::mount;
use crate::mount::Mount;
use crate::partition;

/// Mounts the state partition (or a tmpfs) on `/var` and creates the directories serviced needs
/// there: its log directory, and its persistent layer's, which workload-controller's sandbox
/// binds (it cannot create it). Fails only when `/var` cannot be mounted at all. Blocking:
/// `runtime` reaches trust-controller.
///
/// A `/var` already mounted, by a run that stopped before keeping what it did, is adopted rather
/// than mounted over.
pub fn run(encryption: Encryption, runtime: &Handle) -> anyhow::Result<Backing> {
    let mountinfo = fs::read_to_string(mount::MOUNTINFO).context(mount::MOUNTINFO)?;
    let backing = match Mount::parse_all(&mountinfo)
        .into_iter()
        .rfind(|mount| mount.target == Path::new("/var"))
    {
        Some(mounted) => {
            let backing = adopt(&mounted, encryption, underlying_partition);
            info!(?backing, "/var was mounted by a previous run: adopting it");
            backing
        }
        None => partition::mount_state(encryption, runtime).context("/var cannot be mounted")?,
    };
    let dirs = [Path::new(definition::VAR_LOG_DIR), Layer::Persistent.dir()];
    for dir in dirs {
        if let Err(e) = root_dir(dir) {
            error!(dir = %dir.display(), error = %e, "cannot create the directory");
        }
    }
    info!("/var set up");
    Ok(backing)
}

/// What backs `/var`, from its mount, configured with `encryption`; `partition_of` names the
/// partition under a device-mapper device (`major:minor`).
#[must_use]
fn adopt(
    mounted: &Mount,
    encryption: Encryption,
    partition_of: impl FnOnce(&str) -> Option<PathBuf>,
) -> Backing {
    if mounted.fs_type == "tmpfs" {
        return Backing::Tmpfs {
            encryption,
            reason: "mounted by a previous run, whose reason is lost".into(),
        };
    }
    if mounted.source == encryption::MAPPED {
        // Unlocked or formatted: only the run that opened it knew.
        return Backing::Unlocked {
            partition: partition_of(&mounted.device).unwrap_or_default(),
        };
    }
    Backing::Plain {
        partition: mounted.source.clone().into(),
    }
}

/// The partition under the device-mapper device `device` (`major:minor`), from sysfs.
fn underlying_partition(device: &str) -> Option<PathBuf> {
    let mut slaves = fs::read_dir(format!("/sys/dev/block/{device}/slaves")).ok()?;
    let name = slaves.next()?.ok()?.file_name();
    Some(Path::new("/dev").join(name))
}

/// Creates `path` (and its missing parents), owned by root with mode 0755 whatever was there:
/// serviced's directories. The services' own directories on `/var` are theirs to create (runtime
/// directories, or the program's).
fn root_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    fs::create_dir_all(path)?;
    rustix::fs::chown(path, Some(Uid::ROOT), Some(Gid::ROOT))?;
    fs::set_permissions(path, Permissions::from_mode(0o755))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mounted(fs_type: &str, source: &str) -> Mount {
        Mount {
            device: "253:1".into(),
            target: "/var".into(),
            fs_type: fs_type.into(),
            source: source.into(),
        }
    }

    #[test]
    fn adopts_what_is_mounted() {
        let partition = |device: &str| {
            assert_eq!(device, "253:1");
            Some(PathBuf::from("/dev/vda4"))
        };
        assert_eq!(
            adopt(&mounted("ext4", "/dev/vda4"), Encryption::None, |_| None),
            Backing::Plain {
                partition: "/dev/vda4".into(),
            }
        );
        assert_eq!(
            adopt(
                &mounted("ext4", encryption::MAPPED),
                Encryption::Tpm,
                partition
            ),
            Backing::Unlocked {
                partition: "/dev/vda4".into(),
            }
        );
        assert!(matches!(
            adopt(&mounted("tmpfs", "tmpfs"), Encryption::Tpm, |_| None),
            Backing::Tmpfs {
                encryption: Encryption::Tpm,
                ..
            }
        ));
    }
}

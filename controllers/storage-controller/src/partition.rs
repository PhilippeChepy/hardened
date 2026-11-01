//! The state partition, mounted on `/var`: the only persistent, writable storage.
//!
//! The image ships a small, empty ext4 partition of the systemd "var" type at the end of the
//! boot disk (the one holding the root partition). When the disk has grown since its GPT was
//! written (the backup header is no longer on the last sector), storage-controller extends that
//! partition to the new end, replacing the GUID it has in the image (the same on every machine)
//! by a random one, then grows the mounted filesystem online. Without the partition, or when it
//! does not mount, `/var` falls back to a tmpfs and nothing persists.
//!
//! With `settings.hardened.storage.encryption = "tpm"`, the partition is LUKS2 and `/var` is
//! mounted from its decrypted device ([`encryption`]). Nothing is ever written to it unencrypted
//! then: when it cannot be set up, `/var` is a tmpfs. An encrypted partition is not mounted when
//! encryption is off (also the default of invalid user-data), and is not wiped either.
//!
//! There is no fsck: the journal makes unclean shutdowns safe, metadata checksums detect
//! corruption, and `errors=remount-ro` stops writes to a damaged filesystem.

use std::fs::{self, File, OpenOptions};
use std::io::SeekFrom;
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use gpt::disk::LogicalBlockSize;
use gpt::mbr::ProtectiveMBR;
use gpt::{GptConfig, GptDisk};
use rustix::ioctl::{Opcode, Setter};
use rustix::mount::{self, MountFlags};
use sha2::Sha256;
use storage_controller::Encryption;
use tokio::runtime::Handle;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::backing::Backing;
use crate::encryption;

/// Partition type GUID of the x86-64 root partition, from the Discoverable Partitions
/// Specification.
const ROOT_X86_64: Uuid = uuid::uuid!("4f68bce3-e8cd-4db1-96e7-fbcaf984b709");
/// Partition type GUID of the var partition, from the same specification.
const VAR: Uuid = uuid::uuid!("4d21b016-b534-45c2-a9fb-5c16e091fd2d");
const SECTOR: u64 = 512;
const MIB: u64 = 1 << 20;

/// Finds the state partition, grows it with the disk, decrypts it with `encryption` and mounts
/// it on `/var`; else mounts a tmpfs there. Fails only when even that fails. Blocking: `runtime`
/// reaches trust-controller.
pub fn mount_state(encryption: Encryption, runtime: &Handle) -> anyhow::Result<Backing> {
    match mount_partition(encryption, runtime) {
        Ok(backing) => Ok(backing),
        Err(reason) => mount_tmpfs(encryption, reason),
    }
}

/// Mounts the state partition on `/var`, as [`mount_state`] does; `Err(why)` when it is not used,
/// logged.
fn mount_partition(encryption: Encryption, runtime: &Handle) -> Result<Backing, String> {
    let partition = match prepare() {
        Ok(Some(device)) => device,
        Ok(None) => {
            warn!("no state partition, /var will not persist");
            return Err("no state partition".into());
        }
        Err(e) => {
            warn!(
                error = format!("{e:#}"),
                "state partition unavailable, /var will not persist"
            );
            return Err(format!("state partition unavailable: {e:#}"));
        }
    };
    let backing = match encryption {
        Encryption::None
            if encryption::Content::probe(&partition)
                .is_ok_and(|c| c == encryption::Content::Luks2) =>
        {
            error!(
                device = %partition.display(),
                "the state partition is encrypted, but settings.hardened.storage.encryption is \
                 not \"tpm\": leaving it untouched, /var will not persist"
            );
            return Err("the state partition is encrypted, but encryption is off".into());
        }
        Encryption::None => Backing::Plain { partition },
        Encryption::Tpm => match encryption::open(&partition, runtime) {
            Ok(encryption::Outcome::Unlocked) => Backing::Unlocked { partition },
            Ok(encryption::Outcome::Formatted(reason)) => Backing::Formatted { partition, reason },
            Err(e) => {
                error!(
                    device = %partition.display(),
                    "cannot set up the encrypted state partition, /var will not persist \
                     (nothing is written to the disk unencrypted): {e:#}"
                );
                return Err(format!(
                    "cannot set up the encrypted state partition: {e:#}"
                ));
            }
        },
    };
    let device = match &backing {
        Backing::Plain { partition } => partition.as_path(),
        _ => Path::new(encryption::MAPPED),
    };
    let mounted = mount::mount(
        device,
        "/var",
        "ext4",
        MountFlags::NOATIME,
        c"errors=remount-ro",
    );
    if let Err(e) = mounted {
        warn!(
            device = %device.display(),
            "cannot mount the state partition, /var will not persist: {e}"
        );
        return Err(format!("cannot mount {}: {e}", device.display()));
    }
    info!(device = %device.display(), "state partition mounted on /var");
    if let Err(e) = grow_filesystem(device) {
        warn!(
            device = %device.display(),
            error = format!("{e:#}"),
            "cannot grow the state filesystem"
        );
    }
    Ok(backing)
}

/// Mounts a tmpfs on `/var`, instead of the state partition set up with `encryption`.
fn mount_tmpfs(encryption: Encryption, reason: String) -> anyhow::Result<Backing> {
    mount::mount(
        "tmpfs",
        "/var",
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        c"mode=0755",
    )
    .context("mounting a tmpfs on /var")?;
    Ok(Backing::Tmpfs { encryption, reason })
}

/// The state partition's device, once extended to the end of the disk; `None` without one.
fn prepare() -> anyhow::Result<Option<PathBuf>> {
    let (disk, table) = boot_disk()?;
    let Some((&number, _)) = table
        .partitions()
        .iter()
        .find(|(_, p)| p.part_type_guid.guid == VAR)
    else {
        return Ok(None);
    };
    extend_partition(&disk, &table, number)?;
    wait_for_partition(&disk, number).map(Some)
}

/// The disk holding the root partition (`/dev/vda`), and its partition table.
fn boot_disk() -> anyhow::Result<(PathBuf, GptDisk<File>)> {
    for entry in fs::read_dir("/sys/block")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if ["dm-", "loop", "ram", "zram", "sr"]
            .iter()
            .any(|p| name.starts_with(p))
        {
            continue;
        }
        let path = PathBuf::from("/dev").join(name);
        let opened = GptConfig::new()
            .writable(false)
            .logical_block_size(LogicalBlockSize::Lb512)
            .open(&path);
        let Ok(table) = opened else {
            continue;
        };
        if table
            .partitions()
            .values()
            .any(|p| p.part_type_guid.guid == ROOT_X86_64)
        {
            return Ok((path, table));
        }
    }
    bail!("no disk with a root partition found")
}

/// When the disk has grown, extends the state partition to its new end, rewriting the GPT so
/// its backup header moves to the last sector. A partition still carrying the image's GUID gets a
/// random one; later resizes keep it. Does nothing when the disk has kept its size.
fn extend_partition(disk: &Path, existing: &GptDisk<File>, number: u32) -> anyhow::Result<()> {
    use std::io::Seek as _;

    let mut device = OpenOptions::new().read(true).write(true).open(disk)?;
    let sectors = device.seek(SeekFrom::End(0))? / SECTOR;
    if existing.primary_header()?.backup_lba == sectors - 1 {
        return Ok(());
    }

    let disk_guid = *existing.guid();
    let mut partitions = existing.partitions().clone();
    let last = partitions
        .iter()
        .max_by_key(|(_, p)| p.last_lba)
        .map(|(&n, _)| n);
    ensure!(
        last == Some(number),
        "the state partition is not the last one on the disk"
    );
    let root = partitions
        .values()
        .find(|p| p.part_type_guid.guid == ROOT_X86_64)
        .map(|p| p.part_guid)
        .context("no root partition")?;
    let partition = partitions
        .get_mut(&number)
        .context("state partition vanished")?;
    // Leave 1 MiB for the backup GPT at the end, as the image does, and end on a MiB boundary
    // (whole 4 KiB encryption sectors).
    let end = (sectors - MIB / SECTOR) / (MIB / SECTOR) * (MIB / SECTOR);
    ensure!(
        end > partition.last_lba,
        "the disk is smaller than its partitions"
    );
    partition.last_lba = end - 1;
    if partition.part_guid == image_var_guid(root) {
        partition.part_guid = Uuid::new_v4();
    }
    let (start, length) = (
        partition.first_lba * SECTOR,
        (end - partition.first_lba) * SECTOR,
    );
    let guid = partition.part_guid;

    let mut table = GptConfig::new()
        .writable(true)
        .logical_block_size(LogicalBlockSize::Lb512)
        .create_from_device(device, Some(disk_guid))?;
    table.update_partitions(partitions)?;
    let mut device = table.write()?;
    let mbr_sectors = u32::try_from(sectors - 1).unwrap_or(u32::MAX);
    ProtectiveMBR::with_lb_size(mbr_sectors).overwrite_lba0(&mut device)?;
    device.sync_all()?;

    // The root partition is in use, so the kernel cannot re-read the whole table: resize the
    // state partition explicitly.
    resize_partition(&device, number, start, length)?;
    info!(
        disk = %disk.display(),
        number,
        %guid,
        size_mib = length / MIB,
        "state partition extended to the end of the disk"
    );
    Ok(())
}

/// The state partition's GUID as written in the image, derived from the root partition's. Keep
/// in sync with `image_var_guid` in `image-builder/src/image.rs`.
#[must_use]
fn image_var_guid(root: Uuid) -> Uuid {
    use sha2::Digest as _;

    let digest = Sha256::digest(format!("hardened var partition {root}"));
    uuid::Builder::from_random_bytes(std::array::from_fn(|i| digest[i])).into_uuid()
}

/// Grows the filesystem mounted on `/var` to fill its partition, online. A no-op when it
/// already does (also after an interruption between extending the partition and this).
fn grow_filesystem(device: &Path) -> anyhow::Result<()> {
    /// `_IOW('f', 16, __u64)`, from `<linux/ext4.h>`.
    const EXT4_IOC_RESIZE_FS: Opcode = rustix::ioctl::opcode::write::<u64>(b'f', 16);

    use std::io::{Read as _, Seek as _};

    let mut file = File::open(device)?;
    let size = file.seek(SeekFrom::End(0))?;
    let mut superblock = [0; 1024];
    file.seek(SeekFrom::Start(1024))?;
    file.read_exact(&mut superblock)?;
    // The kernel logs every resize, even an empty one: skip those.
    if ext4_size(&superblock).is_some_and(|ext4| ext4.blocks >= size / ext4.block_size) {
        return Ok(());
    }
    let var = File::open("/var")?;
    let before = rustix::fs::fstatvfs(&var)?;
    let blocks = size / before.f_bsize;
    // SAFETY: EXT4_IOC_RESIZE_FS reads a u64 block count through the pointer, valid for the call.
    unsafe {
        rustix::ioctl::ioctl(&var, Setter::<EXT4_IOC_RESIZE_FS, u64>::new(blocks))?;
    }
    let after = rustix::fs::fstatvfs(&var)?;
    if after.f_blocks > before.f_blocks {
        info!(
            size_mib = after.f_blocks * after.f_bsize / MIB,
            "state filesystem grown to its partition"
        );
    }
    Ok(())
}

/// The size of an ext4 filesystem.
#[derive(Debug, PartialEq, Eq)]
struct Ext4Size {
    blocks: u64,
    /// In bytes.
    block_size: u64,
}

/// The size an ext4 superblock records; `None` if it is not one. On disk, it may lag behind the
/// mounted filesystem: only a grown filesystem has more.
#[must_use]
fn ext4_size(superblock: &[u8; 1024]) -> Option<Ext4Size> {
    let u32_at = |at: usize| u32::from_le_bytes(std::array::from_fn(|i| superblock[at + i]));
    // Offsets of `s_magic`, `s_log_block_size`, `s_feature_incompat` (`INCOMPAT_64BIT`),
    // `s_blocks_count_hi`.
    const MAGIC: usize = 0x38;
    const LOG_BLOCK_SIZE: usize = 0x18;
    const INCOMPAT: usize = 0x60;
    const INCOMPAT_64BIT: u32 = 0x80;
    const BLOCKS_HI: usize = 0x150;
    if superblock[MAGIC..MAGIC + 2] != 0xef53u16.to_le_bytes() {
        return None;
    }
    let block_size = 1024u64.checked_shl(u32_at(LOG_BLOCK_SIZE))?;
    let high = if u32_at(INCOMPAT) & INCOMPAT_64BIT != 0 {
        u64::from(u32_at(BLOCKS_HI))
    } else {
        0
    };
    Some(Ext4Size {
        blocks: high << 32 | u64::from(u32_at(4)),
        block_size,
    })
}

/// Tells the kernel partition `number` of `device` now spans `length` bytes from `start`
/// (`BLKPG_RESIZE_PARTITION`).
fn resize_partition(
    device: &impl AsFd,
    number: u32,
    start: u64,
    length: u64,
) -> anyhow::Result<()> {
    #[repr(C)]
    struct BlkpgPartition {
        start: i64,
        length: i64,
        pno: i32,
        devname: [u8; 64],
        volname: [u8; 64],
    }
    #[repr(C)]
    struct BlkpgIoctlArg {
        op: i32,
        flags: i32,
        datalen: i32,
        data: *mut BlkpgPartition,
    }
    /// From `<linux/blkpg.h>`.
    const BLKPG: Opcode = 0x1269;
    const BLKPG_RESIZE_PARTITION: i32 = 3;

    let mut partition = BlkpgPartition {
        start: i64::try_from(start)?,
        length: i64::try_from(length)?,
        pno: i32::try_from(number)?,
        devname: [0; 64],
        volname: [0; 64],
    };
    let arg = BlkpgIoctlArg {
        op: BLKPG_RESIZE_PARTITION,
        flags: 0,
        datalen: size_of::<BlkpgPartition>() as i32,
        data: &raw mut partition,
    };
    // SAFETY: BLKPG takes a pointer to a blkpg_ioctl_arg whose data points to a blkpg_partition;
    // both live for the duration of the call.
    unsafe {
        rustix::ioctl::ioctl(device, Setter::<BLKPG, BlkpgIoctlArg>::new(arg))?;
    }
    Ok(())
}

/// Waits for the partition's device node (created by devtmpfs on the kernel's uevent).
fn wait_for_partition(disk: &Path, number: u32) -> anyhow::Result<PathBuf> {
    let disk = disk.to_string_lossy();
    let separator = if disk.ends_with(|c: char| c.is_ascii_digit()) {
        "p"
    } else {
        ""
    };
    let device = PathBuf::from(format!("{disk}{separator}{number}"));
    for _ in 0..100 {
        if device.exists() {
            return Ok(device);
        }
        thread::sleep(Duration::from_millis(100));
    }
    bail!("{} did not appear", device.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_ext4_size() {
        let size = |blocks| {
            Some(Ext4Size {
                blocks,
                block_size: 4096,
            })
        };
        let mut superblock = [0; 1024];
        assert_eq!(ext4_size(&superblock), None);
        superblock[0x38..0x3a].copy_from_slice(&[0x53, 0xef]);
        superblock[4..8].copy_from_slice(&16384u32.to_le_bytes());
        superblock[0x18] = 2;
        assert_eq!(ext4_size(&superblock), size(16384));
        superblock[0x150] = 1;
        assert_eq!(ext4_size(&superblock), size(16384), "without 64bit");
        superblock[0x60] = 0x80;
        assert_eq!(ext4_size(&superblock), size((1 << 32) + 16384));
    }

    #[test]
    fn image_var_guid_matches_image_builder() {
        let root = uuid::uuid!("11111111-2222-3333-4444-555555555555");
        assert_eq!(
            image_var_guid(root),
            uuid::uuid!("42f0abe9-1447-4bb0-b4a9-9001a6d578d9")
        );
    }
}

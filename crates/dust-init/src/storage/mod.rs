//! The state partition, mounted on `/var`: the only persistent, writable storage.
//!
//! The image ships a small, empty ext4 partition of the systemd "var" type at the end of the
//! boot disk (the one holding the root partition). When the disk has grown since its GPT was
//! written (the backup header is no longer on the last sector), dust-init extends that partition
//! to the new end, replacing the GUID it has in the image (the same on every machine) by a random
//! one, then grows the mounted filesystem online. Without the partition, or when it does not
//! mount, `/var` falls back to a tmpfs and nothing persists.
//!
//! With `settings.hardened.storage.encryption = "tpm"`, the partition is LUKS2 and `/var` is
//! mounted from its decrypted device ([`encryption`]). Nothing is ever written to it unencrypted
//! then: when it cannot be set up, `/var` is a tmpfs. An encrypted partition is not mounted when
//! encryption is off (which is also the default of invalid user-data), and is not wiped either.
//!
//! There is no fsck: the journal makes unclean shutdowns safe, metadata checksums detect
//! corruption, and `errors=remount-ro` stops writes to a damaged filesystem.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use gpt::disk::LogicalBlockSize;
use rustix::mount::{MountFlags, mount};
use sha2::{Digest, Sha256};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::process::Reaper;
use crate::settings::Encryption;

mod encryption;

/// Partition type GUIDs from the Discoverable Partitions Specification.
const ROOT_X86_64: Uuid = uuid::uuid!("4f68bce3-e8cd-4db1-96e7-fbcaf984b709");
const VAR: Uuid = uuid::uuid!("4d21b016-b534-45c2-a9fb-5c16e091fd2d");
const SECTOR: u64 = 512;
const MIB: u64 = 1 << 20;

/// What backs `/var` on this boot, as the API reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    /// The state partition, unencrypted.
    Plain { partition: PathBuf },
    /// The encrypted state partition, opened with the key the TPM unsealed.
    Unlocked { partition: PathBuf },
    /// The encrypted state partition, formatted on this boot (what it held is gone).
    Formatted { partition: PathBuf, reason: String },
    /// A tmpfs: nothing persists.
    Tmpfs { reason: String },
}

impl State {
    /// The device mounted on `/var`, if not a tmpfs.
    pub fn device(&self) -> Option<&Path> {
        match self {
            Self::Plain { partition } => Some(partition),
            Self::Unlocked { .. } | Self::Formatted { .. } => Some(Path::new(encryption::MAPPED)),
            Self::Tmpfs { .. } => None,
        }
    }
}

/// Finds the state partition, grows it with the disk, decrypts it with `encryption` and mounts it
/// on `/var`.
pub async fn mount_state(reaper: &Reaper, encryption: Encryption) -> anyhow::Result<State> {
    let partition = match prepare().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            warn!("no state partition, /var will not persist");
            return mount_tmpfs("no state partition".into());
        }
        Err(e) => {
            warn!("state partition unavailable, /var will not persist: {e:#}");
            return mount_tmpfs(format!("state partition unavailable: {e:#}"));
        }
    };
    let state = match encryption {
        Encryption::None => {
            if encryption::Content::probe(&partition).is_ok_and(|c| c == encryption::Content::Luks2) {
                error!(
                    device = %partition.display(),
                    "the state partition is encrypted, but settings.hardened.storage.encryption is not \"tpm\": \
                     leaving it untouched, /var will not persist"
                );
                return mount_tmpfs("the state partition is encrypted, but encryption is off".into());
            }
            State::Plain { partition }
        }
        Encryption::Tpm => match encryption::open(reaper, &partition).await {
            Ok(encryption::Outcome::Unlocked) => State::Unlocked { partition },
            Ok(encryption::Outcome::Formatted(reason)) => State::Formatted { partition, reason },
            Err(e) => {
                error!(
                    device = %partition.display(),
                    "cannot set up the encrypted state partition, /var will not persist (nothing is written to \
                     the disk unencrypted): {e:#}"
                );
                return mount_tmpfs(format!("cannot set up the encrypted state partition: {e:#}"));
            }
        },
    };
    let device = state.device().expect("a partition").to_owned();
    if let Err(e) = mount(&device, "/var", "ext4", MountFlags::NOATIME, c"errors=remount-ro") {
        warn!(device = %device.display(), "cannot mount the state partition, /var will not persist: {e}");
        return mount_tmpfs(format!("cannot mount {}: {e}", device.display()));
    }
    info!(device = %device.display(), "state partition mounted on /var");
    let grown = tokio::task::spawn_blocking({
        let device = device.clone();
        move || grow_filesystem(&device)
    })
    .await?;
    if let Err(e) = grown {
        warn!(device = %device.display(), "cannot grow the state filesystem: {e:#}");
    }
    Ok(state)
}

fn mount_tmpfs(reason: String) -> anyhow::Result<State> {
    mount(
        "tmpfs",
        "/var",
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        c"mode=0755",
    )?;
    Ok(State::Tmpfs { reason })
}

async fn prepare() -> anyhow::Result<Option<PathBuf>> {
    let disk = boot_disk()?;
    let partitions = open_table(&disk.path)?.partitions().clone();
    let Some((&number, _)) = partitions.iter().find(|(_, p)| p.part_type_guid.guid == VAR) else {
        return Ok(None);
    };
    extend_partition(&disk, number)?;
    wait_for_partition(&disk, number).await.map(Some)
}

fn open_table(path: &Path) -> anyhow::Result<gpt::GptDisk<File>> {
    gpt::GptConfig::new()
        .writable(false)
        .logical_block_size(LogicalBlockSize::Lb512)
        .open(path)
        .with_context(|| format!("reading the GPT of {}", path.display()))
}

/// A whole disk, e.g. `/dev/vda` (sysfs name `vda`).
struct Disk {
    name: String,
    path: PathBuf,
}

/// The disk holding the root partition.
fn boot_disk() -> anyhow::Result<Disk> {
    for entry in std::fs::read_dir("/sys/block")? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if ["dm-", "loop", "ram", "zram", "sr"].iter().any(|p| name.starts_with(p)) {
            continue;
        }
        let path = PathBuf::from("/dev").join(&name);
        let Ok(disk) = open_table(&path) else {
            continue;
        };
        if disk.partitions().values().any(|p| p.part_type_guid.guid == ROOT_X86_64) {
            return Ok(Disk { name, path });
        }
    }
    bail!("no disk with a root partition found")
}

/// When the disk has grown, extends the state partition to its new end, rewriting the GPT so its
/// backup header moves to the last sector. A partition still carrying the image's GUID gets a
/// random one; later resizes keep it. Does nothing when the disk has kept its size.
fn extend_partition(disk: &Disk, number: u32) -> anyhow::Result<()> {
    let mut device = OpenOptions::new().read(true).write(true).open(&disk.path)?;
    let sectors = device.seek(SeekFrom::End(0))? / SECTOR;
    let existing = open_table(&disk.path)?;
    if existing.primary_header()?.backup_lba == sectors - 1 {
        return Ok(());
    }

    let disk_guid = *existing.guid();
    let mut partitions = existing.partitions().clone();
    let last = partitions.iter().max_by_key(|(_, p)| p.last_lba).map(|(&n, _)| n);
    ensure!(
        last == Some(number),
        "the state partition is not the last one on the disk"
    );
    let root = partitions
        .values()
        .find(|p| p.part_type_guid.guid == ROOT_X86_64)
        .map(|p| p.part_guid)
        .context("no root partition")?;
    let partition = partitions.get_mut(&number).context("state partition vanished")?;
    // Leave 1 MiB for the backup GPT at the end, as the image does, and end on a MiB boundary
    // (whole 4 KiB encryption sectors).
    let end = (sectors - MIB / SECTOR) / (MIB / SECTOR) * (MIB / SECTOR);
    ensure!(end > partition.last_lba, "the disk is smaller than its partitions");
    partition.last_lba = end - 1;
    if partition.part_guid == image_var_guid(root) {
        partition.part_guid = Uuid::new_v4();
    }
    let (start, length) = (partition.first_lba * SECTOR, (end - partition.first_lba) * SECTOR);
    let guid = partition.part_guid;

    let mut table = gpt::GptConfig::new()
        .writable(true)
        .logical_block_size(LogicalBlockSize::Lb512)
        .create_from_device(device, Some(disk_guid))?;
    table.update_partitions(partitions)?;
    let mut device = table.write()?;
    let mbr_sectors = u32::try_from(sectors - 1).unwrap_or(u32::MAX);
    gpt::mbr::ProtectiveMBR::with_lb_size(mbr_sectors).overwrite_lba0(&mut device)?;
    device.sync_all()?;

    // The root partition is in use, so the kernel cannot re-read the whole table: resize the
    // state partition explicitly.
    blkpg(&device, Blkpg::ResizePartition, number, start, length)?;
    info!(disk = %disk.path.display(), number, %guid, size_mib = length / MIB, "state partition extended to the end of the disk");
    Ok(())
}

/// The state partition's GUID as written in the image, derived from the root partition's. Keep in
/// sync with `image_var_guid` in `crates/dust-builder/src/image.rs`.
fn image_var_guid(root: Uuid) -> Uuid {
    let digest = Sha256::digest(format!("hardened var partition {root}"));
    uuid::Builder::from_random_bytes(digest[..16].try_into().expect("16 of 32 bytes")).into_uuid()
}

/// Grows the filesystem mounted on `/var` to fill its partition, online. A no-op when it
/// already does (also after an interruption between extending the partition and this).
fn grow_filesystem(device: &Path) -> anyhow::Result<()> {
    /// `_IOW('f', 16, __u64)`, from `<linux/ext4.h>`.
    const EXT4_IOC_RESIZE_FS: rustix::ioctl::Opcode = rustix::ioctl::opcode::write::<u64>(b'f', 16);

    let mut file = File::open(device)?;
    let size = file.seek(SeekFrom::End(0))?;
    let mut superblock = [0; 1024];
    file.seek(SeekFrom::Start(1024))?;
    file.read_exact(&mut superblock)?;
    // The kernel logs every resize, even an empty one: skip those.
    if ext4_blocks(&superblock).is_some_and(|(blocks, block_size)| blocks >= size / block_size) {
        return Ok(());
    }
    let var = File::open("/var")?;
    let before = rustix::fs::fstatvfs(&var)?;
    let blocks = size / before.f_bsize;
    // SAFETY: EXT4_IOC_RESIZE_FS reads a u64 block count through the pointer, valid for the call.
    unsafe {
        rustix::ioctl::ioctl(&var, rustix::ioctl::Setter::<EXT4_IOC_RESIZE_FS, u64>::new(blocks))?;
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

/// The block count and block size an ext4 superblock records; `None` if it is not one. On disk,
/// it may lag behind the mounted filesystem: only a grown filesystem has more.
fn ext4_blocks(superblock: &[u8; 1024]) -> Option<(u64, u64)> {
    let u32_at = |at: usize| u32::from_le_bytes(superblock[at..at + 4].try_into().expect("4 bytes"));
    /// `s_magic`, `s_log_block_size`, `s_feature_incompat` (`INCOMPAT_64BIT`), `s_blocks_count_hi`.
    const MAGIC: usize = 0x38;
    const LOG_BLOCK_SIZE: usize = 0x18;
    const INCOMPAT: usize = 0x60;
    const INCOMPAT_64BIT: u32 = 0x80;
    const BLOCKS_HI: usize = 0x150;
    if superblock[MAGIC..MAGIC + 2] != 0xEF53u16.to_le_bytes() {
        return None;
    }
    let block_size = 1024u64.checked_shl(u32_at(LOG_BLOCK_SIZE))?;
    let high = if u32_at(INCOMPAT) & INCOMPAT_64BIT != 0 {
        u64::from(u32_at(BLOCKS_HI))
    } else {
        0
    };
    Some((high << 32 | u64::from(u32_at(4)), block_size))
}

/// Operations of the `BLKPG` ioctl, from `<linux/blkpg.h>`.
#[repr(i32)]
enum Blkpg {
    ResizePartition = 3,
}

fn blkpg(device: &impl AsFd, op: Blkpg, number: u32, start: u64, length: u64) -> anyhow::Result<()> {
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
    const BLKPG: rustix::ioctl::Opcode = 0x1269;

    let mut partition = BlkpgPartition {
        start: i64::try_from(start)?,
        length: i64::try_from(length)?,
        pno: i32::try_from(number)?,
        devname: [0; 64],
        volname: [0; 64],
    };
    let arg = BlkpgIoctlArg {
        op: op as i32,
        flags: 0,
        datalen: size_of::<BlkpgPartition>() as i32,
        data: &raw mut partition,
    };
    // SAFETY: BLKPG takes a pointer to a blkpg_ioctl_arg whose data points to a blkpg_partition;
    // both live for the duration of the call.
    unsafe {
        rustix::ioctl::ioctl(device, rustix::ioctl::Setter::<BLKPG, BlkpgIoctlArg>::new(arg))?;
    }
    Ok(())
}

/// Waits for the partition's device node (created by devtmpfs on the kernel's uevent).
async fn wait_for_partition(disk: &Disk, number: u32) -> anyhow::Result<PathBuf> {
    let suffix = if disk.name.ends_with(|c: char| c.is_ascii_digit()) {
        format!("p{number}")
    } else {
        number.to_string()
    };
    let device = PathBuf::from(format!("/dev/{}{suffix}", disk.name));
    for _ in 0..100 {
        if device.exists() {
            return Ok(device);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!("{} did not appear", device.display())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_ext4_block_count() {
        let mut superblock = [0; 1024];
        assert_eq!(ext4_blocks(&superblock), None);
        superblock[0x38..0x3A].copy_from_slice(&[0x53, 0xEF]);
        superblock[4..8].copy_from_slice(&16384u32.to_le_bytes());
        superblock[0x18] = 2;
        assert_eq!(ext4_blocks(&superblock), Some((16384, 4096)));
        superblock[0x150] = 1;
        assert_eq!(ext4_blocks(&superblock), Some((16384, 4096)), "without 64bit");
        superblock[0x60] = 0x80;
        assert_eq!(ext4_blocks(&superblock), Some(((1 << 32) + 16384, 4096)));
    }

    #[test]
    fn image_var_guid_matches_dust_builder() {
        let root = uuid::uuid!("11111111-2222-3333-4444-555555555555");
        assert_eq!(
            image_var_guid(root),
            uuid::uuid!("42f0abe9-1447-4bb0-b4a9-9001a6d578d9")
        );
    }
}

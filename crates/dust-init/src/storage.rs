//! The state partition, mounted on `/var`: the only persistent, writable storage.
//!
//! The image ships a small, empty ext4 partition of the systemd "var" type at the end of the
//! boot disk (the one holding the root partition). When the disk has grown since its GPT was
//! written (the backup header is no longer on the last sector), dust-init extends that partition
//! to the new end, replacing the GUID it has in the image (the same on every machine) by a random
//! one, then grows the mounted filesystem online. Without the partition, or when it does not
//! mount, `/var` falls back to a tmpfs and nothing persists.
//!
//! There is no fsck: the journal makes unclean shutdowns safe, metadata checksums detect
//! corruption, and `errors=remount-ro` stops writes to a damaged filesystem.

use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, bail, ensure};
use gpt::disk::LogicalBlockSize;
use rustix::mount::{MountFlags, mount};
use sha2::{Digest, Sha256};
use tracing::{info, warn};
use uuid::Uuid;

/// Partition type GUIDs from the Discoverable Partitions Specification.
const ROOT_X86_64: Uuid = uuid::uuid!("4f68bce3-e8cd-4db1-96e7-fbcaf984b709");
const VAR: Uuid = uuid::uuid!("4d21b016-b534-45c2-a9fb-5c16e091fd2d");
const SECTOR: u64 = 512;
const MIB: u64 = 1 << 20;

/// What backs `/var`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum State {
    Partition(PathBuf),
    Tmpfs,
}

/// Finds the state partition, grows it with the disk and mounts it on `/var`.
pub async fn mount_state() -> anyhow::Result<State> {
    let device = match prepare().await {
        Ok(Some(device)) => device,
        Ok(None) => {
            warn!("no state partition, /var will not persist");
            return mount_tmpfs();
        }
        Err(e) => {
            warn!("state partition unavailable, /var will not persist: {e:#}");
            return mount_tmpfs();
        }
    };
    if let Err(e) = mount(&device, "/var", "ext4", MountFlags::NOATIME, c"errors=remount-ro") {
        warn!(device = %device.display(), "cannot mount the state partition, /var will not persist: {e}");
        return mount_tmpfs();
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
    Ok(State::Partition(device))
}

fn mount_tmpfs() -> anyhow::Result<State> {
    mount(
        "tmpfs",
        "/var",
        "tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        c"mode=0755",
    )?;
    Ok(State::Tmpfs)
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
    // Leave 1 MiB for the backup GPT at the end, as the image does.
    let end = sectors - MIB / SECTOR;
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

    let size = File::open(device)?.seek(SeekFrom::End(0))?;
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
    fn image_var_guid_matches_dust_builder() {
        let root = uuid::uuid!("11111111-2222-3333-4444-555555555555");
        assert_eq!(
            image_var_guid(root),
            uuid::uuid!("42f0abe9-1447-4bb0-b4a9-9001a6d578d9")
        );
    }
}

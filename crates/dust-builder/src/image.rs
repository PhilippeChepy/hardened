//! OS image assembly.
//!
//! ```text
//! GPT disk
//! ├── 1 esp                 FAT32, /EFI/BOOT/BOOTX64.EFI = signed UKI (systemd-stub + kernel +
//! │                         command line carrying the dm-verity root hash)
//! ├── 2 root-x86-64         erofs root filesystem (read-only)
//! ├── 3 root-x86-64-verity  dm-verity hash tree of partition 2
//! └── 4 var                 empty ext4 state filesystem, grown by dust-init to fill the disk
//! ```
//!
//! There is no initramfs: the kernel's dm-init (`dm-mod.create=`) opens the verity device and
//! mounts it as `/`, then runs dust-init, which mounts partition 4 on `/var`. The partition UUIDs of the root and its hash tree are derived from
//! the root hash (as systemd-repart does), the other identifiers from the root filesystem
//! manifest, so identical inputs produce an identical image.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use gpt::partition_types::{OperatingSystem, Type};
use uuid::{Uuid, uuid};

use crate::Paths;
use crate::build::Built;
use crate::components::{kernel, systemd_stub};
use crate::podman::Builder;
use crate::recipe::{ComponentName, Recipes};
use crate::sha256::Sha256;

const MIB: u64 = 1 << 20;
const SECTOR: u64 = 512;
const ESP_SIZE: u64 = 64 * MIB;
const VERITY_BLOCK: u64 = 4096;
/// Initial size of the state partition; dust-init grows it to the end of the disk.
const VAR_SIZE: u64 = 64 * MIB;

const ESP_TYPE: Uuid = uuid!("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
const ROOT_X86_64_TYPE: Uuid = uuid!("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");
const ROOT_X86_64_VERITY_TYPE: Uuid = uuid!("2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5");
const VAR_TYPE: Uuid = uuid!("4D21B016-B534-45C2-A9FB-5C16E091FD2D");
/// GPT attribute bit 60: read-only.
const GPT_FLAG_READ_ONLY: u64 = 1 << 60;

/// Hardening options added to the kernel command line.
const KERNEL_HARDENING: &str =
    "slab_nomerge init_on_free=1 page_alloc.shuffle=1 randomize_kstack_offset=on lockdown=integrity";

/// Builds every component and writes the image, its SBOM and file manifest to `build/out/`.
pub fn build_image(paths: &Paths) -> anyhow::Result<()> {
    let version = crate::recipe::WORKSPACE_VERSION;
    let recipes = Recipes::load()?;
    let builder = Builder::ensure(paths)?;
    let order = recipes.build_order(&[])?;
    crate::fetch::fetch_all(paths, order.iter().copied())?;
    let built = crate::build::build_all(paths, &builder, &order, None)?;
    let ordered: Vec<&Built> = order.iter().map(|r| &built[r.name()]).collect();

    let dir = paths.image();
    std::fs::create_dir_all(&dir)?;

    eprintln!("==> assembling root filesystem");
    let rootfs = dir.join("rootfs");
    let mut manifest = crate::rootfs::assemble(&ordered, &rootfs)?;
    for component in &ordered {
        for image in component.recipe.images() {
            let archive = std::fs::read(component.container_image(image))?;
            let path = format!("{}/{}.tar", crate::oci::IMAGES_DIR, image.name);
            manifest.add_generated(&rootfs, &path, component.recipe.name(), &archive, 0o644)?;
        }
    }
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    std::fs::write(dir.join("manifest.json"), &manifest_json)?;
    let manifest_digest = Sha256::digest(&manifest_json);

    eprintln!("==> sealing root filesystem (erofs + dm-verity)");
    let verity = seal_rootfs(&builder, &dir, &rootfs, &manifest_digest)?;
    format_state(&builder, &dir, &manifest_digest)?;

    eprintln!("==> building unified kernel image");
    let release = std::fs::read_to_string(crate::build::locate(&built, &kernel::RELEASE)?)?
        .trim()
        .to_owned();
    let cmdline = kernel_cmdline(&verity);
    std::fs::write(dir.join("cmdline"), &cmdline)?;
    let uki = build_uki(paths, &builder, &built, &dir, &release)?;

    eprintln!("==> writing disk image");
    let esp = dir.join("esp.img");
    write_esp(&esp, &uki, &manifest_digest)?;
    let raw = dir.join("disk.raw");
    write_disk(
        &raw,
        &esp,
        &dir.join("root.erofs"),
        &dir.join("root.verity"),
        &dir.join("var.ext4"),
        &verity,
        &manifest_digest,
    )?;

    let out = paths.out();
    std::fs::create_dir_all(&out)?;
    let base = format!("hardened-{version}-x86_64");
    let qcow2 = out.join(format!("{base}.qcow2"));
    builder
        .container(format!(
            "qemu-img convert -f raw -O qcow2 -c -o compression_type=zlib /image/disk.raw /out/{base}.qcow2"
        ))
        .mount_ro(&dir, "/image")
        .mount(&out, "/out")
        .run()?;

    eprintln!("==> writing SBOM");
    let sbom = out.join(format!("{base}.cdx.json"));
    let document = crate::sbom::Sbom {
        version,
        components: &ordered,
        builder: &builder,
        manifest: &manifest,
        image_sha256: Sha256::of_file(&qcow2)?,
        roothash: verity.roothash,
        cmdline: &cmdline,
    }
    .render()?;
    std::fs::write(&sbom, serde_json::to_vec_pretty(&document)?)?;
    std::fs::write(out.join(format!("{base}.manifest.json")), &manifest_json)?;
    std::fs::copy(&uki, out.join(format!("{base}.efi")))?;
    std::fs::write(out.join(format!("{base}.roothash")), format!("{}\n", verity.roothash))?;

    let layout = crate::report::render(&raw, &esp, &manifest)?;
    std::fs::write(out.join(format!("{base}.layout.txt")), &layout)?;
    eprintln!("\n{layout}");

    eprintln!("==> {}", qcow2.display());
    eprintln!("==> {}", sbom.display());
    Ok(())
}

/// The dm-verity parameters of the sealed root filesystem.
#[derive(Debug)]
struct Verity {
    roothash: Sha256,
    salt: Sha256,
    /// Size of the (non-empty) erofs image, in verity blocks.
    data_blocks: NonZeroU64,
    /// Size of the hash tree, in bytes.
    hash_size: u64,
}

impl Verity {
    fn data_size(&self) -> u64 {
        self.data_blocks.get() * VERITY_BLOCK
    }

    /// Partition UUIDs derived from the root hash (first and second half), like systemd-repart.
    fn partition_uuids(&self) -> (Uuid, Uuid) {
        let (data, hash) = self.roothash.halves();
        (Uuid::from_bytes(data), Uuid::from_bytes(hash))
    }
}

fn seal_rootfs(builder: &Builder, dir: &Path, rootfs: &Path, manifest_digest: &Sha256) -> anyhow::Result<Verity> {
    let fs_uuid = derived_uuid(manifest_digest, "erofs");
    let salt = Sha256::digest(format!("hardened verity salt {manifest_digest}"));
    let output = builder
        .container(format!(
            "rm -f /image/root.erofs /image/root.verity\n\
             mkfs.erofs --quiet -zlz4hc --all-root --ignore-mtime -T {epoch} -U {fs_uuid} \
               /image/root.erofs /rootfs >&2\n\
             veritysetup format --no-superblock --hash sha256 --data-block-size {VERITY_BLOCK} \
               --hash-block-size {VERITY_BLOCK} --salt {salt} /image/root.erofs /image/root.verity",
            epoch = crate::SOURCE_DATE_EPOCH,
        ))
        .mount_ro(rootfs, "/rootfs")
        .mount(dir, "/image")
        .output()?;

    let roothash = output
        .lines()
        .find_map(|line| line.strip_prefix("Root hash:"))
        .context("veritysetup did not print a root hash")?
        .trim()
        .parse()?;
    let data_size = std::fs::metadata(dir.join("root.erofs"))?.len();
    let hash_size = std::fs::metadata(dir.join("root.verity"))?.len();
    ensure!(
        data_size % VERITY_BLOCK == 0,
        "erofs image is not a multiple of the verity block size"
    );
    let data_blocks = NonZeroU64::new(data_size / VERITY_BLOCK).context("empty root filesystem")?;
    Ok(Verity {
        roothash,
        salt,
        data_blocks,
        hash_size,
    })
}

/// Formats the empty state filesystem, reproducibly: fixed UUID, directory hash seed and
/// timestamps. 4 KiB blocks and `64bit` let the kernel grow it online to any disk size.
fn format_state(builder: &Builder, dir: &Path, manifest_digest: &Sha256) -> anyhow::Result<()> {
    let fs_uuid = derived_uuid(manifest_digest, "var filesystem");
    let hash_seed = derived_uuid(manifest_digest, "var hash seed");
    builder
        .container(format!(
            "rm -f /image/var.ext4\n\
             E2FSPROGS_FAKE_TIME={epoch} SOURCE_DATE_EPOCH={epoch} mke2fs -q -t ext4 -b 4096 -O 64bit \
               -L STATE -U {fs_uuid} -E hash_seed={hash_seed},root_owner=0:0,lazy_itable_init=0 \
               /image/var.ext4 {size}k",
            epoch = crate::SOURCE_DATE_EPOCH,
            size = VAR_SIZE / 1024,
        ))
        .mount(dir, "/image")
        .run()?;
    Ok(())
}

fn kernel_cmdline(verity: &Verity) -> String {
    let (data, hash) = verity.partition_uuids();
    let sectors = verity.data_size() / SECTOR;
    let blocks = verity.data_blocks;
    let table = format!(
        "0 {sectors} verity 1 PARTUUID={data} PARTUUID={hash} {VERITY_BLOCK} {VERITY_BLOCK} {blocks} 0 \
         sha256 {roothash} {salt} 1 restart_on_corruption",
        roothash = verity.roothash,
        salt = verity.salt,
    );
    format!(
        "console=tty0 console=ttyS0,115200n8 \
         dm-mod.waitfor=PARTUUID={data},PARTUUID={hash} dm-mod.create=\"root,,,ro,{table}\" \
         root=/dev/dm-0 rootfstype=erofs ro init=/usr/bin/dust-init panic=10 raid=noautodetect {KERNEL_HARDENING}"
    )
}

/// Builds the UKI with ukify and signs it with the Secure Boot key in `build/keys`.
fn build_uki(
    paths: &Paths,
    builder: &Builder,
    built: &BTreeMap<ComponentName, Built>,
    dir: &Path,
    release: &str,
) -> anyhow::Result<PathBuf> {
    crate::keys::ensure(paths, builder)?;
    let keys = paths.keys();
    builder
        .container(format!(
            "python3 /uki/assembler build --efi-arch x64 --stub /uki/stub \
               --linux /uki/linux --uname {release} --cmdline @/image/cmdline \
               --os-release @/rootfs/usr/lib/os-release \
               --signtool sbsign --secureboot-private-key /keys/db.key --secureboot-certificate /keys/db.crt \
               --output /image/uki.efi >&2"
        ))
        .mount_ro(crate::build::locate(built, &systemd_stub::UKIFY)?, "/uki/assembler")
        .mount_ro(crate::build::locate(built, &systemd_stub::STUB)?, "/uki/stub")
        .mount_ro(crate::build::locate(built, &kernel::IMAGE)?, "/uki/linux")
        .mount_ro(dir.join("rootfs"), "/rootfs")
        .mount_ro(keys.join("db.key"), "/keys/db.key")
        .mount_ro(keys.join("db.crt"), "/keys/db.crt")
        .mount(dir, "/image")
        .run()?;
    Ok(dir.join("uki.efi"))
}

fn write_esp(path: &Path, uki: &Path, manifest_digest: &Sha256) -> anyhow::Result<()> {
    let uki_bytes = std::fs::read(uki)?;
    ensure!(
        (uki_bytes.len() as u64) < ESP_SIZE - 4 * MIB,
        "UKI ({} bytes) does not fit in the ESP",
        uki_bytes.len()
    );

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(ESP_SIZE)?;
    let volume_id = u32::from_be_bytes(Sha256::digest(format!("esp {manifest_digest}")).prefix());
    fatfs::format_volume(
        &mut file,
        fatfs::FormatVolumeOptions::new()
            .fat_type(fatfs::FatType::Fat32)
            .bytes_per_cluster(512)
            .volume_id(volume_id)
            .volume_label(*b"ESP        "),
    )?;
    file.seek(SeekFrom::Start(0))?;

    // Without the `chrono` feature, fatfs stamps every entry with a fixed date (1980-01-01).
    let fs = fatfs::FileSystem::new(&mut file, fatfs::FsOptions::new())?;
    {
        let boot = fs.root_dir().create_dir("EFI")?.create_dir("BOOT")?;
        boot.create_file("BOOTX64.EFI")?.write_all(&uki_bytes)?;
    }
    fs.unmount()?;
    Ok(())
}

fn write_disk(
    path: &Path,
    esp: &Path,
    root: &Path,
    hash: &Path,
    var: &Path,
    verity: &Verity,
    manifest_digest: &Sha256,
) -> anyhow::Result<()> {
    let align = |n: u64| n.div_ceil(MIB) * MIB;
    let esp_start = MIB;
    let root_start = esp_start + ESP_SIZE;
    let hash_start = root_start + align(verity.data_size());
    let var_start = hash_start + align(verity.hash_size);
    // Room for the backup GPT.
    let total = var_start + VAR_SIZE + MIB;

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(total)?;
    for (source, offset) in [
        (esp, esp_start),
        (root, root_start),
        (hash, hash_start),
        (var, var_start),
    ] {
        file.seek(SeekFrom::Start(offset))?;
        std::io::copy(&mut File::open(source)?, &mut file)?;
    }

    let (root_uuid, hash_uuid) = verity.partition_uuids();
    let part = |type_guid: Uuid, guid: Uuid, start: u64, size: u64, flags: u64, name: &str| gpt::partition::Partition {
        part_type_guid: Type {
            guid: type_guid,
            os: OperatingSystem::None,
        },
        part_guid: guid,
        first_lba: start / SECTOR,
        last_lba: (start + size) / SECTOR - 1,
        flags,
        name: name.to_owned(),
    };
    let partitions = BTreeMap::from([
        (
            1,
            part(
                ESP_TYPE,
                derived_uuid(manifest_digest, "esp"),
                esp_start,
                ESP_SIZE,
                0,
                "esp",
            ),
        ),
        (
            2,
            part(
                ROOT_X86_64_TYPE,
                root_uuid,
                root_start,
                align(verity.data_size()),
                GPT_FLAG_READ_ONLY,
                "root-x86-64",
            ),
        ),
        (
            3,
            part(
                ROOT_X86_64_VERITY_TYPE,
                hash_uuid,
                hash_start,
                align(verity.hash_size),
                GPT_FLAG_READ_ONLY,
                "root-x86-64-verity",
            ),
        ),
        // dust-init gives it a random GUID when it first extends it.
        (
            4,
            part(VAR_TYPE, image_var_guid(root_uuid), var_start, VAR_SIZE, 0, "var"),
        ),
    ]);

    let mut disk = gpt::GptConfig::new()
        .writable(true)
        .logical_block_size(gpt::disk::LogicalBlockSize::Lb512)
        .create_from_device(file, Some(derived_uuid(manifest_digest, "disk")))?;
    disk.update_partitions(partitions)?;
    let mut file = disk.write()?;
    let sectors = u32::try_from(total / SECTOR - 1).unwrap_or(u32::MAX);
    gpt::mbr::ProtectiveMBR::with_lb_size(sectors).overwrite_lba0(&mut file)?;
    file.sync_all()?;
    Ok(())
}

/// The state partition's GUID in the image, derived from the root partition's so dust-init can
/// recognize it (and replace it) without knowing anything else about the image. Keep in sync
/// with `image_var_guid` in `crates/dust-init/src/storage.rs`.
fn image_var_guid(root: Uuid) -> Uuid {
    uuid::Builder::from_random_bytes(Sha256::digest(format!("hardened var partition {root}")).prefix()).into_uuid()
}

/// A stable UUID (version 4 layout) derived from the image content and a purpose label.
fn derived_uuid(digest: &Sha256, purpose: &str) -> Uuid {
    uuid::Builder::from_random_bytes(Sha256::digest(format!("hardened {purpose} {digest}")).prefix()).into_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_var_guid_matches_dust_init() {
        let root = uuid!("11111111-2222-3333-4444-555555555555");
        assert_eq!(image_var_guid(root), uuid!("42f0abe9-1447-4bb0-b4a9-9001a6d578d9"));
    }

    #[test]
    fn cmdline_carries_the_verity_table() {
        let verity = Verity {
            roothash: ("11".repeat(16) + &"22".repeat(16)).parse().unwrap(),
            salt: "ab".repeat(32).parse().unwrap(),
            data_blocks: NonZeroU64::new(8).unwrap(),
            hash_size: VERITY_BLOCK,
        };
        let cmdline = kernel_cmdline(&verity);
        assert!(cmdline.contains(
            "dm-mod.create=\"root,,,ro,0 64 verity 1 PARTUUID=11111111-1111-1111-1111-111111111111 \
             PARTUUID=22222222-2222-2222-2222-222222222222 4096 4096 8 0 sha256"
        ));
        assert!(cmdline.contains(&format!(
            "{} {} 1 restart_on_corruption",
            "11".repeat(16) + &"22".repeat(16),
            "ab".repeat(32)
        )));
        assert!(cmdline.contains("init=/usr/bin/dust-init "));
    }

    #[test]
    fn derived_uuids_are_stable_and_distinct() {
        let digest = Sha256::digest(b"d");
        assert_eq!(derived_uuid(&digest, "esp"), derived_uuid(&digest, "esp"));
        assert_ne!(derived_uuid(&digest, "esp"), derived_uuid(&digest, "disk"));
    }
}

//! OS image assembly.
//!
//! ```text
//! GPT disk
//! ├── 1 esp                 FAT32, /EFI/BOOT/BOOTX64.EFI = signed UKI (systemd-stub + kernel +
//! │                         command line carrying the dm-verity root hash)
//! ├── 2 root-x86-64         erofs root filesystem (read-only)
//! ├── 3 root-x86-64-verity  dm-verity hash tree of partition 2
//! └── 4 var                 empty ext4 state filesystem, grown to fill the disk
//! ```
//!
//! There is no initramfs: the kernel's dm-init (`dm-mod.create=`) opens the verity device and
//! mounts it as `/`, then runs serviced, whose storage-controller service mounts partition 4 on
//! `/var`. The partition UUIDs of the root and its hash tree are derived from the root hash (as
//! systemd-repart does), the other identifiers from the root filesystem manifest, so identical
//! inputs produce an identical image.

use std::collections::BTreeMap;
use std::fmt::Display;
use std::fs::{self, File, OpenOptions};
use std::io::{self, ErrorKind, Seek, SeekFrom};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use fatfs::{FatType, FileSystem, FormatVolumeOptions, FsOptions};
use gpt::GptConfig;
use gpt::disk::LogicalBlockSize;
use gpt::mbr::ProtectiveMBR;
use gpt::partition_types::{OperatingSystem, Type};
use uuid::{Uuid, uuid};

use crate::build::{Built, Options};
use crate::pipeline::Pipeline;
use crate::podman::Image;
use crate::recipe::{Output, Unit};
use crate::rootfs::Manifest;
use crate::sbom::Sbom;
use crate::sha256::Sha256;
use crate::targets::{Format, Partition};
use crate::{Paths, name};

const MIB: u64 = 1 << 20;
const SECTOR: u64 = 512;
const VERITY_BLOCK: u64 = 4096;
/// Where the ESP starts on the disk, after the GPT.
const ESP_START: u64 = MIB;

/// Partition types (systemd's discoverable partitions).
pub const ESP_TYPE: Uuid = uuid!("C12A7328-F81F-11D2-BA4B-00A0C93EC93B");
pub const ROOT_X86_64_TYPE: Uuid = uuid!("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");
pub const ROOT_X86_64_VERITY_TYPE: Uuid = uuid!("2C7357ED-EBD2-46D9-AEC1-23D437EC2BF5");
pub const VAR_TYPE: Uuid = uuid!("4D21B016-B534-45C2-A9FB-5C16E091FD2D");
/// GPT attribute bit 60: read-only.
const GPT_FLAG_READ_ONLY: u64 = 1 << 60;

/// The outputs the image is made of, besides the root filesystem: the kernel (a component of the
/// exported target) and its release, the UKI's stub and ukify (systemd-stub, in the image of its
/// `export.environment`).
const KERNEL_IMAGE: Output = Output::new(name!("kernel"), "bzImage");
const KERNEL_RELEASE: Output = Output::new(name!("kernel"), "kernel.release");
const KERNEL_CONFIG: Output = Output::new(name!("kernel"), "config");
const UKI_STUB: Output = Output::new(name!("systemd-stub"), "linuxx64.efi.stub");
const UKIFY: Output = Output::new(name!("systemd-stub"), "ukify");

/// The option the test variant adds to the kernel command line (see [`TEST_VARIANT`]).
const TEST_VARIANT_OPTION: &str = "hardened.test-variant=1";
/// The test variant of an image: a disk holding only an ESP, with a UKI whose command line has
/// [`TEST_VARIANT_OPTION`] too. Booted from it, with the image's disk attached, the machine runs
/// the same root filesystem, but systemd-stub measures another UKI into PCR 11: to the TPM, it is
/// another image.
pub const TEST_VARIANT: &str = "boot-variant.raw";

/// The disks [`build_image`] writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disks {
    /// The image's.
    Image,
    /// The image's, and its [`TEST_VARIANT`] next to it.
    WithTestVariant,
}

/// Builds the target `target_id` (its components, the tools exporting it, and what they need),
/// and writes its image, SBOM and file manifest to `build/out/`, and its `disks`.
pub fn build_image(
    paths: &Paths,
    target_id: &str,
    options: Options,
    disks: Disks,
) -> anyhow::Result<()> {
    let version = crate::recipe::WORKSPACE_VERSION;
    let pipeline = Pipeline::load(paths)?;
    let target = pipeline.targets.get(target_id)?;
    let export = (target.export.as_ref())
        .with_context(|| format!("target {} is not exported", target.id))?;
    let Format::Qcow2 = export.format;
    let tools = pipeline.export_environment(target)?;

    let content = target.units();
    let find = |units: &[Unit], output: &Output, what: &str| -> anyhow::Result<Unit> {
        let unit = (units.iter())
            .find(|unit| unit.component == *output.component())
            .with_context(|| format!("no {} in {what}", output.component()))?;
        let job = pipeline.job(unit)?;
        ensure!(
            job.recipe.plan.outputs.contains(output.name()),
            "{unit} writes no {}, which the image needs",
            output.name()
        );
        Ok(unit.clone())
    };
    let kernel = find(&content, &KERNEL_IMAGE, &format!("target {}", target.id))?;
    find(&content, &KERNEL_RELEASE, &format!("target {}", target.id))?;
    find(&content, &KERNEL_CONFIG, &format!("target {}", target.id))?;
    let tools_name = format!("the image of target {}", export.environment);
    let stub = find(&tools.trees, &UKI_STUB, &tools_name)?;
    find(&tools.trees, &UKIFY, &tools_name)?;

    let mut selected = content.clone();
    selected.extend(tools.trees.iter().cloned());
    let order = pipeline.order(&selected)?;
    crate::fetch::fetch_all(paths, order.iter().map(|job| &job.recipe))?;
    let built =
        crate::build::build_all(paths, &order, &pipeline.keys_environment()?, &[], options)?;
    let assembly = crate::environment::ensure(paths, &tools, &built)?;
    let ordered: Vec<&Built<'_>> = order.iter().map(|job| &built[&job.unit]).collect();
    let shipped: Vec<&Built<'_>> = content.iter().map(|unit| &built[unit]).collect();

    let dir = paths.image(target.id.as_str());
    fs::create_dir_all(&dir)?;

    eprintln!("==> assembling root filesystem of target {}", target.id);
    let rootfs = dir.join("rootfs");
    let mut manifest = crate::rootfs::assemble(&shipped, &rootfs)?;
    for component in &shipped {
        for image in &component.job.recipe.plan.images {
            let archive = fs::read(component.container_image(image))?;
            let path = format!("{}/{}.tar", crate::oci::IMAGES_DIR, image.name);
            manifest.add_generated(&rootfs, &path, component.job.recipe.name(), &archive)?;
        }
    }
    strip(&assembly, &rootfs, &mut manifest)?;
    let manifest_json = serde_json::to_vec_pretty(&manifest)?;
    fs::write(dir.join("manifest.json"), &manifest_json)?;
    let manifest_digest = Sha256::digest(&manifest_json);

    eprintln!("==> sealing root filesystem (erofs + dm-verity)");
    let verity = seal_rootfs(&assembly, &dir, &rootfs, &manifest_digest)?;
    format_state(
        &assembly,
        &dir,
        &manifest_digest,
        target.partition.state_size,
    )?;

    eprintln!("==> building unified kernel image");
    let release = fs::read_to_string(crate::build::locate(&built, &kernel, &KERNEL_RELEASE)?)?
        .trim()
        .to_owned();
    let cmdline = kernel_cmdline(&verity, &target.kernel_cmdline);
    fs::write(dir.join("cmdline"), &cmdline)?;
    crate::kspp::check(
        &assembly,
        &crate::build::locate(&built, &kernel, &KERNEL_CONFIG)?,
        &dir.join("cmdline"),
        target
            .kspp_sysctls
            .as_ref()
            .map(|path| rootfs.join(path.trim_start_matches('/')))
            .as_deref(),
        &target.kspp_exceptions,
    )?;
    // The UKI of the command line `cmdline<suffix>`, and the ESP `esp<suffix>.img` holding it.
    let write_boot = |suffix: &str| -> anyhow::Result<(PathBuf, PathBuf)> {
        let uki = build_uki(
            paths,
            &assembly,
            &built,
            (&kernel, &stub),
            &dir,
            &release,
            suffix,
        )?;
        let esp = dir.join(format!("esp{suffix}.img"));
        write_esp(&esp, &uki, &manifest_digest, target.partition.esp_size)?;
        Ok((uki, esp))
    };
    let (uki, esp) = write_boot("")?;

    eprintln!("==> writing disk image");
    let raw = dir.join("disk.raw");
    write_disk(&raw, &dir, &verity, &manifest_digest, &target.partition)?;
    if disks == Disks::WithTestVariant {
        eprintln!("==> writing the test variant ({TEST_VARIANT_OPTION})");
        fs::write(
            dir.join("cmdline-variant"),
            format!("{cmdline} {TEST_VARIANT_OPTION}"),
        )?;
        let (_, esp) = write_boot("-variant")?;
        // A disk holding only the ESP.
        let partition = GptEntry {
            type_guid: ESP_TYPE,
            guid: derived_uuid("variant esp", manifest_digest),
            start: ESP_START,
            size: target.partition.esp_size,
            flags: 0,
            name: "esp",
        };
        let guid = derived_uuid("variant disk", manifest_digest);
        write_gpt(&dir.join(TEST_VARIANT), guid, &[(partition, esp)])?;
    } else if let Err(e) = fs::remove_file(dir.join(TEST_VARIANT))
        && e.kind() != ErrorKind::NotFound
    {
        return Err(e.into());
    }

    let out = paths.out();
    fs::create_dir_all(&out)?;
    let base = format!("{}-{version}-x86_64", export.name);
    let qcow2 = out.join(format!("{base}.qcow2"));
    assembly
        .container()
        .mount_ro(&dir, "/image")
        .mount(&out, "/out")
        .run(&format!(
            "qemu-img convert -f raw -O qcow2 -c -o compression_type=zlib \
             /image/disk.raw /out/{base}.qcow2"
        ))?;

    eprintln!("==> writing SBOM");
    let sbom = out.join(format!("{base}.cdx.json"));
    let document = Sbom {
        version,
        components: &ordered,
        bootstrap: &pipeline
            .seeds()
            .flat_map(|seed| seed.images.iter().cloned())
            .collect::<Vec<_>>(),
        manifest: &manifest,
        image_sha256: Sha256::of_file(&qcow2)?,
        roothash: verity.roothash,
        cmdline: &cmdline,
    }
    .render()?;
    fs::write(&sbom, serde_json::to_vec_pretty(&document)?)?;
    fs::write(out.join(format!("{base}.manifest.json")), &manifest_json)?;
    fs::copy(&uki, out.join(format!("{base}.efi")))?;
    // The values a verifier expects (`hctl attest verify --expected`).
    let pcr11 = crate::pcr11::expected(&fs::read(&uki)?).context("computing PCR 11")?;
    let expected = serde_json::json!({ "sha256": { "11": pcr11.to_string() } });
    fs::write(
        out.join(format!("{base}.pcrs.json")),
        serde_json::to_vec_pretty(&expected)?,
    )?;
    fs::write(
        out.join(format!("{base}.roothash")),
        format!("{}\n", verity.roothash),
    )?;

    let layout = crate::report::render(&raw, &esp, &manifest)?;
    fs::write(out.join(format!("{base}.layout.txt")), &layout)?;
    eprintln!("\n{layout}");

    eprintln!("==> {}", qcow2.display());
    eprintln!("==> {}", sbom.display());
    Ok(())
}

/// Strips the executables of the root filesystem with the tools' `llvm-strip`, once for all: C
/// programs keep their symbol tables unless their build strips them, and Rust's release profile
/// keeps them too. `--strip-all` on an executable is deterministic; kernel modules are left
/// alone (their signature covers them).
fn strip(image: &Image, rootfs: &Path, manifest: &mut Manifest) -> anyhow::Result<()> {
    let paths = crate::rootfs::unstripped(rootfs, manifest)?;
    if paths.is_empty() {
        return Ok(());
    }
    eprintln!(
        "==> stripping {}",
        paths
            .iter()
            .map(|p| format!("/{p}"))
            .collect::<Vec<_>>()
            .join(" ")
    );
    let files: Vec<String> = paths.iter().map(|path| format!("/rootfs/{path}")).collect();
    image
        .container()
        .mount(rootfs, "/rootfs")
        .run(&format!("llvm-strip --strip-all {}", files.join(" ")))?;
    manifest.rehash(rootfs, &paths)?;
    let left = crate::rootfs::unstripped(rootfs, manifest)?;
    ensure!(
        left.is_empty(),
        "still unstripped after llvm-strip: {}",
        left.join(", ")
    );
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

fn seal_rootfs(
    image: &Image,
    dir: &Path,
    rootfs: &Path,
    manifest_digest: &Sha256,
) -> anyhow::Result<Verity> {
    let fs_uuid = derived_uuid("erofs", manifest_digest);
    let salt = Sha256::digest(format!("hardened verity salt {manifest_digest}"));
    let output = image
        .container()
        .mount_ro(rootfs, "/rootfs")
        .mount(dir, "/image")
        .output(&format!(
            "rm -f /image/root.erofs /image/root.verity\n\
             mkfs.erofs --quiet -zlz4hc,12 --all-root --ignore-mtime -T {epoch} -U {fs_uuid} \
               /image/root.erofs /rootfs >&2\n\
             veritysetup format --no-superblock --hash sha256 --data-block-size {VERITY_BLOCK} \
               --hash-block-size {VERITY_BLOCK} --salt {salt} /image/root.erofs /image/root.verity",
            epoch = crate::SOURCE_DATE_EPOCH,
        ))?;

    let roothash = output
        .lines()
        .find_map(|line| line.strip_prefix("Root hash:"))
        .context("veritysetup did not print a root hash")?
        .trim()
        .parse()?;
    let data_size = fs::metadata(dir.join("root.erofs"))?.len();
    let hash_size = fs::metadata(dir.join("root.verity"))?.len();
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
fn format_state(
    image: &Image,
    dir: &Path,
    manifest_digest: &Sha256,
    size: u64,
) -> anyhow::Result<()> {
    let fs_uuid = derived_uuid("var filesystem", manifest_digest);
    let hash_seed = derived_uuid("var hash seed", manifest_digest);
    image.container().mount(dir, "/image").run(&format!(
        "rm -f /image/var.ext4\n\
         E2FSPROGS_FAKE_TIME={epoch} SOURCE_DATE_EPOCH={epoch} \
           mke2fs -q -t ext4 -b 4096 -O 64bit -L STATE -U {fs_uuid} \
           -E hash_seed={hash_seed},root_owner=0:0,lazy_itable_init=0 \
           /image/var.ext4 {size}k",
        epoch = crate::SOURCE_DATE_EPOCH,
        size = size / 1024,
    ))
}

/// The command line: the console, the verity root and serviced, then the target's `extra`
/// options.
#[must_use]
fn kernel_cmdline(verity: &Verity, extra: &[String]) -> String {
    let (data, hash) = verity.partition_uuids();
    let sectors = verity.data_size() / SECTOR;
    let blocks = verity.data_blocks;
    let table = format!(
        "0 {sectors} verity 1 PARTUUID={data} PARTUUID={hash} \
         {VERITY_BLOCK} {VERITY_BLOCK} {blocks} 0 sha256 {roothash} {salt} 1 restart_on_corruption",
        roothash = verity.roothash,
        salt = verity.salt,
    );
    format!(
        "console=tty0 console=ttyS0,115200n8 \
         dm-mod.waitfor=PARTUUID={data},PARTUUID={hash} dm-mod.create=\"root,,,ro,{table}\" \
         root=/dev/dm-0 rootfstype=erofs ro init=/usr/bin/serviced panic=10 raid=noautodetect {}",
        extra.join(" ")
    )
}

/// Builds the UKI with ukify and signs it, and the kernel inside, with the Secure Boot key in
/// `build/keys`. `--sign-kernel` is explicit: systemd-sbsign cannot check if it is signed already.
/// The signatures' signing time is `SOURCE_DATE_EPOCH`, otherwise the current time. Its command
/// line is `dir/cmdline<suffix>`, and it is written to `dir/uki<suffix>.efi`.
fn build_uki(
    paths: &Paths,
    image: &Image,
    built: &BTreeMap<Unit, Built<'_>>,
    (kernel, stub): (&Unit, &Unit),
    dir: &Path,
    release: &str,
    suffix: &str,
) -> anyhow::Result<PathBuf> {
    let keys = paths.keys();
    image
        .container()
        .mount_ro(crate::build::locate(built, stub, &UKIFY)?, "/uki/assembler")
        .mount_ro(crate::build::locate(built, stub, &UKI_STUB)?, "/uki/stub")
        .mount_ro(
            crate::build::locate(built, kernel, &KERNEL_IMAGE)?,
            "/uki/linux",
        )
        .mount_ro(dir.join("rootfs"), "/rootfs")
        .mount_ro(keys.join("db.key"), "/keys/db.key")
        .mount_ro(keys.join("db.crt"), "/keys/db.crt")
        .mount(dir, "/image")
        .env("SOURCE_DATE_EPOCH", crate::SOURCE_DATE_EPOCH.to_string())
        .run(&format!(
            "python3 /uki/assembler build --efi-arch x64 --stub /uki/stub \
               --linux /uki/linux --uname {release} --cmdline @/image/cmdline{suffix} \
               --os-release @/rootfs/usr/lib/os-release \
               --signtool systemd-sbsign --sign-kernel \
               --secureboot-private-key /keys/db.key --secureboot-certificate /keys/db.crt \
               --output /image/uki{suffix}.efi >&2"
        ))?;
    Ok(dir.join(format!("uki{suffix}.efi")))
}

fn write_esp(path: &Path, uki: &Path, manifest_digest: &Sha256, size: u64) -> anyhow::Result<()> {
    use std::io::Write as _;

    let uki_bytes = fs::read(uki)?;
    ensure!(
        (uki_bytes.len() as u64) < size.saturating_sub(4 * MIB),
        "UKI ({} bytes) does not fit in the ESP",
        uki_bytes.len()
    );

    let mut file = create_sized(path, size)?;
    let volume_id = u32::from_be_bytes(Sha256::digest(format!("esp {manifest_digest}")).prefix());
    fatfs::format_volume(
        &mut file,
        FormatVolumeOptions::new()
            .fat_type(FatType::Fat32)
            .bytes_per_cluster(512)
            .volume_id(volume_id)
            .volume_label(*b"ESP        "),
    )?;
    file.seek(SeekFrom::Start(0))?;

    // Without the `chrono` feature, fatfs stamps every entry with a fixed date (1980-01-01).
    let esp = FileSystem::new(&mut file, FsOptions::new())?;
    {
        let boot = esp.root_dir().create_dir("EFI")?.create_dir("BOOT")?;
        boot.create_file("BOOTX64.EFI")?.write_all(&uki_bytes)?;
    }
    esp.unmount()?;
    Ok(())
}

/// Writes the disk `path` from the partitions written in `dir`.
fn write_disk(
    path: &Path,
    dir: &Path,
    verity: &Verity,
    manifest_digest: &Sha256,
    partition: &Partition,
) -> anyhow::Result<()> {
    let (esp_size, var_size) = (partition.esp_size, partition.state_size);
    let align = |n: u64| n.div_ceil(MIB) * MIB;
    let esp_start = ESP_START;
    let root_start = esp_start + esp_size;
    let hash_start = root_start + align(verity.data_size());
    let var_start = hash_start + align(verity.hash_size);

    let (root_uuid, hash_uuid) = verity.partition_uuids();
    let partitions = [
        GptEntry {
            type_guid: ESP_TYPE,
            guid: derived_uuid("esp", manifest_digest),
            start: esp_start,
            size: esp_size,
            flags: 0,
            name: "esp",
        },
        GptEntry {
            type_guid: ROOT_X86_64_TYPE,
            guid: root_uuid,
            start: root_start,
            size: align(verity.data_size()),
            flags: GPT_FLAG_READ_ONLY,
            name: "root-x86-64",
        },
        GptEntry {
            type_guid: ROOT_X86_64_VERITY_TYPE,
            guid: hash_uuid,
            start: hash_start,
            size: align(verity.hash_size),
            flags: GPT_FLAG_READ_ONLY,
            name: "root-x86-64-verity",
        },
        // storage-controller gives the state partition a random GUID when it first extends it.
        GptEntry {
            type_guid: VAR_TYPE,
            guid: image_var_guid(root_uuid),
            start: var_start,
            size: var_size,
            flags: 0,
            name: "var",
        },
    ];
    let contents = ["esp.img", "root.erofs", "root.verity", "var.ext4"].map(|f| dir.join(f));
    let partitions: Vec<_> = partitions.into_iter().zip(contents).collect();
    write_gpt(path, derived_uuid("disk", manifest_digest), &partitions)
}

/// Writes the GPT disk `path` (identified by `guid`) of `partitions`, each with the contents of
/// its file, in order.
fn write_gpt(path: &Path, guid: Uuid, partitions: &[(GptEntry, PathBuf)]) -> anyhow::Result<()> {
    // Room for the backup GPT after the last partition.
    let total = partitions
        .iter()
        .map(|(p, _)| p.start + p.size)
        .max()
        .unwrap_or(0)
        + MIB;
    let mut file = create_sized(path, total)?;
    for (partition, contents) in partitions {
        file.seek(SeekFrom::Start(partition.start))?;
        io::copy(&mut File::open(contents)?, &mut file)?;
    }
    let mut disk = GptConfig::new()
        .writable(true)
        .logical_block_size(LogicalBlockSize::Lb512)
        .create_from_device(file, Some(guid))?;
    disk.update_partitions(
        (1..)
            .zip(partitions.iter().map(|(p, _)| p.to_partition()))
            .collect(),
    )?;
    let mut file = disk.write()?;
    let sectors = u32::try_from(total / SECTOR - 1).unwrap_or(u32::MAX);
    ProtectiveMBR::with_lb_size(sectors).overwrite_lba0(&mut file)?;
    file.sync_all()?;
    Ok(())
}

/// A partition of the disk image.
#[derive(Debug, Clone, Copy)]
struct GptEntry {
    type_guid: Uuid,
    guid: Uuid,
    /// Offset on the disk, in bytes.
    start: u64,
    /// In bytes.
    size: u64,
    /// GPT attribute bits.
    flags: u64,
    name: &'static str,
}

impl GptEntry {
    fn to_partition(self) -> gpt::partition::Partition {
        gpt::partition::Partition {
            part_type_guid: Type {
                guid: self.type_guid,
                os: OperatingSystem::None,
            },
            part_guid: self.guid,
            first_lba: self.start / SECTOR,
            last_lba: (self.start + self.size) / SECTOR - 1,
            flags: self.flags,
            name: self.name.to_owned(),
        }
    }
}

/// A new file of `size` bytes, zeroed.
fn create_sized(path: &Path, size: u64) -> anyhow::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.set_len(size)?;
    Ok(file)
}

/// The state partition's GUID in the image, derived from the root partition's so
/// storage-controller can recognize it (and replace it) without knowing anything else about the
/// image. Keep in sync with `image_var_guid` in `controllers/storage-controller/src/partition.rs`.
#[must_use]
fn image_var_guid(root: Uuid) -> Uuid {
    derived_uuid("var partition", root)
}

/// A stable UUID (version 4 layout) derived from a purpose label and a seed (the image content).
#[must_use]
fn derived_uuid(purpose: &str, seed: impl Display) -> Uuid {
    uuid::Builder::from_random_bytes(Sha256::digest(format!("hardened {purpose} {seed}")).prefix())
        .into_uuid()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_var_guid_matches_storage_controller() {
        let root = uuid!("11111111-2222-3333-4444-555555555555");
        assert_eq!(
            image_var_guid(root),
            uuid!("42f0abe9-1447-4bb0-b4a9-9001a6d578d9")
        );
    }

    #[test]
    fn cmdline_carries_the_verity_table() {
        let verity = Verity {
            roothash: ("11".repeat(16) + &"22".repeat(16)).parse().unwrap(),
            salt: "ab".repeat(32).parse().unwrap(),
            data_blocks: NonZeroU64::new(8).unwrap(),
            hash_size: VERITY_BLOCK,
        };
        let cmdline = kernel_cmdline(&verity, &["lockdown=integrity".to_owned()]);
        assert!(cmdline.contains(
            "dm-mod.create=\"root,,,ro,0 64 verity 1 PARTUUID=11111111-1111-1111-1111-111111111111 \
             PARTUUID=22222222-2222-2222-2222-222222222222 4096 4096 8 0 sha256"
        ));
        assert!(cmdline.contains(&format!(
            "{} {} 1 restart_on_corruption",
            "11".repeat(16) + &"22".repeat(16),
            "ab".repeat(32)
        )));
        assert!(cmdline.contains("init=/usr/bin/serviced "));
        assert!(cmdline.ends_with(" raid=noautodetect lockdown=integrity"));
    }
}

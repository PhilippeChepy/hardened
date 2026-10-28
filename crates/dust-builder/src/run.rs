//! Booting the image in qemu, in a container of the target's test environment (`[export] test`):
//! OVMF firmware, an swtpm vTPM, user-data through fw_cfg, the dust API forwarded to the host.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, ensure};

use crate::podman::Image;
use crate::{Paths, TargetArg};

#[derive(clap::Args)]
pub struct RunArgs {
    #[command(flatten)]
    target: TargetArg,
    /// User-data file passed to the VM.
    #[arg(long)]
    user_data: Option<PathBuf>,
    /// Size of the virtual disk; dust-init grows the state partition to fill it.
    #[arg(long, default_value = "8G")]
    disk_size: String,
    /// Keep the disk, TPM and UEFI variables of the previous run.
    #[arg(long)]
    keep_state: bool,
    #[arg(long, default_value_t = 2048)]
    memory_mib: u32,
    /// Host port the dust API (7443) is forwarded to.
    #[arg(long, default_value_t = 7443)]
    api_port: u16,
}

#[derive(clap::Args)]
pub struct TestArgs {
    #[command(flatten)]
    target: TargetArg,
    /// Seconds to wait for every marker.
    #[arg(long, default_value_t = 300)]
    timeout: u64,
    /// Reuse the existing image instead of rebuilding it.
    #[arg(long)]
    no_build: bool,
}

/// A boot of the smoke test.
struct Boot {
    name: &'static str,
    /// A disk the firmware boots from instead of the image's (its test variant), if any.
    boot_disk: Option<&'static str>,
    tpm: Tpm,
    /// The console lines it waits for, in order.
    markers: &'static [&'static str],
    /// The console lines it waits for, in any order (those of concurrent tasks).
    unordered: &'static [&'static str],
}

/// The vTPM of a boot.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Tpm {
    /// The one the previous boot left.
    Kept,
    /// A new one, as when the TPM is cleared or the disk moves to another machine.
    Cleared,
    /// No TPM at all.
    Absent,
}

/// The boots of the smoke test (see `tests/smoke-user-data.toml`), each on the disk the previous
/// one left. The first formats the encrypted state partition, and sees dust-ntp synchronize the
/// clock (with pool.ntp.org: the test needs the Internet, as for its image); the second unseals its key and
/// finds the state of the first (containerd's store, with the bundled images); the third boots
/// another image (PCR 11 differs), which cannot unseal the key and formats the partition again;
/// the fourth, that image with a cleared TPM, formats it again too. The fifth has no TPM: `/var`
/// is a tmpfs, the partition left alone, as the sixth shows by unlocking it with the TPM back.
const SMOKE_BOOTS: &[Boot] = &[
    Boot {
        name: "first boot",
        boot_disk: None,
        tpm: Tpm::Kept,
        markers: &[
            "dust-init: state partition formatted with encryption",
            "dust-init: state partition mounted on /var device=/dev/mapper/state",
            "dust-init: boot complete",
            "hello from a hardened workload",
            "workload hello exited with code 0",
        ],
        unordered: &["INFO clock synchronized"],
    },
    Boot {
        name: "second boot, same disk and TPM",
        boot_disk: None,
        tpm: Tpm::Kept,
        markers: &[
            "dust-init: state partition unlocked with the TPM",
            "dust-init: state partition mounted on /var device=/dev/mapper/state",
            "already imported",
            "dust-init: boot complete",
            "hello from a hardened workload",
            "workload hello exited with code 0",
        ],
        unordered: &[],
    },
    Boot {
        name: "third boot, another image on the same disk and TPM",
        boot_disk: Some(crate::image::TEST_VARIANT),
        tpm: Tpm::Kept,
        markers: &[
            "its key is sealed to another image (PCR 11 differs)",
            "dust-init: state partition formatted with encryption",
            "dust-init: state partition mounted on /var device=/dev/mapper/state",
            "dust-init: imported bundled image",
            "dust-init: boot complete",
        ],
        unordered: &[],
    },
    Boot {
        name: "fourth boot, that image with a cleared TPM",
        boot_disk: Some(crate::image::TEST_VARIANT),
        tpm: Tpm::Cleared,
        markers: &[
            "the TPM cannot unseal its key (another or a cleared TPM)",
            "dust-init: state partition formatted with encryption",
            "dust-init: state partition mounted on /var device=/dev/mapper/state",
            "dust-init: imported bundled image",
            "dust-init: boot complete",
        ],
        unordered: &[],
    },
    Boot {
        name: "fifth boot, without a TPM",
        boot_disk: Some(crate::image::TEST_VARIANT),
        tpm: Tpm::Absent,
        markers: &[
            "cannot set up the encrypted state partition, /var will not persist",
            "dust-init: imported bundled image",
            "dust-init: boot complete",
            "hello from a hardened workload",
        ],
        unordered: &[],
    },
    Boot {
        name: "sixth boot, the TPM back",
        boot_disk: Some(crate::image::TEST_VARIANT),
        tpm: Tpm::Kept,
        markers: &[
            "dust-init: state partition unlocked with the TPM",
            "dust-init: state partition mounted on /var device=/dev/mapper/state",
            "already imported",
            "dust-init: boot complete",
        ],
        unordered: &[],
    },
];

pub fn run(paths: &Paths, args: &RunArgs) -> anyhow::Result<()> {
    let vm = vm_image(paths, &args.target)?;
    let image = latest_image(paths, &args.target)?;
    let state = paths.build().join("run");
    let mut cmd = qemu_container(&vm, &image, None, Tpm::Kept, &state, args)?
        .interactive()
        .command();
    let status = cmd.status()?;
    ensure!(status.success(), "qemu exited with {status}");
    Ok(())
}

pub fn test(paths: &Paths, args: &TestArgs) -> anyhow::Result<()> {
    if !args.no_build {
        crate::image::build_image(paths, &args.target.id, crate::build::Options::default(), true)?;
    }
    let vm = vm_image(paths, &args.target)?;
    let image = latest_image(paths, &args.target)?;
    ensure!(
        image.with_file_name(crate::image::TEST_VARIANT).exists(),
        "no test variant of target {0}: run `cargo builder test --target {0}` without --no-build",
        args.target.id
    );
    let state = paths.build().join("test");
    for (i, boot) in SMOKE_BOOTS.iter().enumerate() {
        eprintln!("==> {}", boot.name);
        let run_args = RunArgs {
            target: args.target.clone(),
            user_data: Some(paths.root.join("tests/smoke-user-data.toml")),
            disk_size: "4G".into(),
            keep_state: i > 0,
            memory_mib: 2048,
            api_port: 17443,
        };
        if boot.tpm == Tpm::Cleared {
            std::fs::remove_dir_all(state.join("tpm"))?;
        }
        boot_until(&vm, &image, &state, &run_args, boot, Duration::from_secs(args.timeout)).context(boot.name)?;
    }
    eprintln!("==> smoke test passed");
    Ok(())
}

/// Boots the image (from `boot.boot_disk` if any) until the console has shown every marker, in order, then stops the VM.
fn boot_until(
    vm: &Image,
    image: &Path,
    state: &Path,
    run_args: &RunArgs,
    boot: &Boot,
    timeout: Duration,
) -> anyhow::Result<()> {
    let name = format!("hardened-test-{}", std::process::id());
    let mut child = qemu_container(vm, image, boot.boot_disk, boot.tpm, state, run_args)?
        .name(&name)
        .command()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;

    let (tx, rx) = mpsc::channel();
    let stdout = child.stdout.take().context("qemu stdout")?;
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            println!("{line}");
            if tx.send(line).is_err() {
                break;
            }
        }
    });

    let deadline = Instant::now() + timeout;
    let mut pending = boot.markers.iter().peekable();
    let mut unordered: Vec<&str> = boot.unordered.to_vec();
    let result = loop {
        let next = pending.peek();
        if next.is_none() && unordered.is_empty() {
            break Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let line = match rx.recv_timeout(remaining) {
            Ok(line) => line,
            Err(_) => {
                let waited: Vec<&str> = next.map(|marker| **marker).into_iter().chain(unordered).collect();
                break Err(anyhow::anyhow!("timed out waiting for {waited:?}"));
            }
        };
        if line.contains("Kernel panic") {
            break Err(anyhow::anyhow!("kernel panic"));
        }
        if next.is_some_and(|marker| line.contains(*marker)) {
            pending.next();
        }
        unordered.retain(|marker| !line.contains(marker));
    };
    // Stopped abruptly, as by a crash: what was flushed (the LUKS2 header, the filesystem's
    // journal) must be enough for the next boot.
    crate::podman::remove(&name);
    let _ = child.kill();
    let _ = child.wait();
    result
}

fn latest_image(paths: &Paths, target: &TargetArg) -> anyhow::Result<PathBuf> {
    let image = paths.image(&target.id).join("disk.raw");
    ensure!(
        image.exists(),
        "no image of target {0}: run `cargo builder image --target {0}` first",
        target.id
    );
    Ok(image)
}

/// The VM booting `image`, whose writes go to an overlay in `state`; or, with `boot_disk` (a file
/// next to `image`), booting from that disk, read-only, with the image's attached. The TPM's
/// state is kept in `state` too.
fn qemu_container<'a>(
    vm: &'a Image,
    image: &Path,
    boot_disk: Option<&str>,
    tpm: Tpm,
    state: &Path,
    args: &RunArgs,
) -> anyhow::Result<crate::podman::Container<'a>> {
    if !args.keep_state && state.exists() {
        std::fs::remove_dir_all(state)?;
    }
    std::fs::create_dir_all(state.join("tpm"))?;

    let user_data = match &args.user_data {
        Some(path) => {
            let dest = state.join("user-data");
            std::fs::copy(path, &dest).with_context(|| path.display().to_string())?;
            "-fw_cfg name=opt/hardened/user-data,file=/state/user-data"
        }
        None => "",
    };
    let script = format!(
        r#"
[ -f /state/disk.qcow2 ] || qemu-img create -q -f qcow2 -F raw -b /image/disk.raw /state/disk.qcow2 {size}
[ -f /state/vars.fd ] || cp /usr/share/OVMF/OVMF_VARS_4M.fd /state/vars.fd
{swtpm}accel=tcg; [ -w /dev/kvm ] && accel=kvm
exec qemu-system-x86_64 -nodefaults -nographic -serial mon:stdio \
    -machine q35,accel=$accel -cpu max -smp 2 -m {memory} \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=/state/vars.fd \
    -drive file=/state/disk.qcow2,if=none,id=disk,format=qcow2 -device virtio-blk-pci,drive=disk,bootindex=1 \
    {boot_disk} \
    -netdev user,id=net0,hostfwd=tcp::7443-:7443 -device virtio-net-pci,netdev=net0,romfile= \
    {tpm_device} \
    -device virtio-rng-pci \
    {user_data}
"#,
        size = args.disk_size,
        boot_disk = boot_disk
            .map(|disk| {
                format!(
                    "-drive file=/image/{disk},if=none,id=boot,format=raw,readonly=on \
                     -device virtio-blk-pci,drive=boot,bootindex=0"
                )
            })
            .unwrap_or_default(),
        memory = args.memory_mib,
        swtpm = if tpm == Tpm::Absent { "" } else { SWTPM },
        tpm_device = if tpm == Tpm::Absent { "" } else { TPM_DEVICE },
    );
    let mut container = vm
        .container(script)
        .mount_ro(image.parent().context("image directory")?, "/image")
        .mount(state, "/state")
        .network(true)
        .publish(format!("127.0.0.1:{}:7443", args.api_port));
    if Path::new("/dev/kvm").exists() {
        container = container.device("/dev/kvm");
    }
    Ok(container)
}

/// Starts the vTPM, its state in `/state/tpm`.
const SWTPM: &str = r#"rm -f /state/swtpm.sock
swtpm socket --tpm2 --tpmstate dir=/state/tpm --ctrl type=unixio,path=/state/swtpm.sock \
    --flags startup-clear --daemon
for _ in $(seq 50); do [ -S /state/swtpm.sock ] && break; sleep 0.1; done
"#;

const TPM_DEVICE: &str =
    "-chardev socket,id=tpm,path=/state/swtpm.sock -tpmdev emulator,id=tpm0,chardev=tpm -device tpm-crb,tpmdev=tpm0";

/// The image of the target's test environment (qemu, OVMF, swtpm and what the script above
/// runs), its components built if needed.
fn vm_image(paths: &Paths, target: &TargetArg) -> anyhow::Result<Image> {
    let pipeline = crate::pipeline::Pipeline::load(paths)?;
    let target = pipeline.targets.get(&target.id)?;
    anyhow::ensure!(target.export.is_some(), "target {} is not exported", target.id);
    let environment = pipeline.environment(target)?;
    let order = pipeline.order(&environment.trees)?;
    crate::fetch::fetch_all(paths, order.iter().map(|job| &job.recipe))?;
    let built = crate::build::build_all(
        paths,
        &order,
        &pipeline.keys_environment()?,
        None,
        crate::build::Options::default(),
    )?;
    crate::environment::ensure(paths, &environment, &built)
}

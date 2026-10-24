//! Booting the image in qemu (inside the builder container): OVMF firmware, an swtpm vTPM,
//! user-data through fw_cfg, the dust API forwarded to the host.

use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail};

use crate::Paths;
use crate::podman::Builder;

#[derive(clap::Args)]
pub struct RunArgs {
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
    /// Seconds to wait for every marker.
    #[arg(long, default_value_t = 300)]
    timeout: u64,
    /// Reuse the existing image instead of rebuilding it.
    #[arg(long)]
    no_build: bool,
}

/// Console lines the smoke test waits for, in order (see `tests/smoke-user-data.toml`).
const SMOKE_MARKERS: &[&str] = &[
    "dust-init: boot complete",
    "hello from a hardened workload",
    "workload hello exited with code 0",
];

pub fn run(paths: &Paths, args: &RunArgs) -> anyhow::Result<()> {
    let builder = Builder::ensure(paths)?;
    let image = latest_image(paths)?;
    let state = paths.build().join("run");
    let mut cmd = qemu_container(&builder, &image, &state, args)?
        .interactive(true)
        .command();
    let status = cmd.status()?;
    if !status.success() {
        bail!("qemu exited with {status}");
    }
    Ok(())
}

pub fn test(paths: &Paths, args: &TestArgs) -> anyhow::Result<()> {
    if !args.no_build {
        crate::image::build_image(paths)?;
    }
    let builder = Builder::ensure(paths)?;
    let image = latest_image(paths)?;
    let state = paths.build().join("test");
    let run_args = RunArgs {
        user_data: Some(paths.root.join("tests/smoke-user-data.toml")),
        disk_size: "4G".into(),
        keep_state: false,
        memory_mib: 2048,
        api_port: 17443,
    };
    let name = format!("hardened-test-{}", std::process::id());
    let mut child = qemu_container(&builder, &image, &state, &run_args)?
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

    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let mut pending = SMOKE_MARKERS.iter().peekable();
    let result = loop {
        let Some(marker) = pending.peek() else { break Ok(()) };
        let remaining = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(remaining) {
            Ok(line) if line.contains(*marker) => {
                pending.next();
            }
            Ok(line) if line.contains("Kernel panic") => break Err(anyhow::anyhow!("kernel panic")),
            Ok(_) => {}
            Err(_) => break Err(anyhow::anyhow!("timed out waiting for {marker:?}")),
        }
    };
    crate::podman::remove(&name);
    let _ = child.kill();
    let _ = child.wait();
    result?;
    eprintln!("==> smoke test passed");
    Ok(())
}

fn latest_image(paths: &Paths) -> anyhow::Result<PathBuf> {
    let image = paths.image().join("disk.raw");
    if !image.exists() {
        bail!("no image: run `cargo builder image` first");
    }
    Ok(image)
}

fn qemu_container<'a>(
    builder: &'a Builder,
    image: &Path,
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
[ -f /state/disk.qcow2 ] || qemu-img create -q -f qcow2 -F raw -b /image/disk.raw /state/disk.qcow2 {disk}
[ -f /state/vars.fd ] || cp /usr/share/OVMF/OVMF_VARS_4M.fd /state/vars.fd
swtpm socket --tpm2 --tpmstate dir=/state/tpm --ctrl type=unixio,path=/state/swtpm.sock \
    --flags startup-clear --daemon
for _ in $(seq 50); do [ -S /state/swtpm.sock ] && break; sleep 0.1; done
accel=tcg; [ -w /dev/kvm ] && accel=kvm
exec qemu-system-x86_64 -nodefaults -nographic -serial mon:stdio \
    -machine q35,accel=$accel -cpu max -smp 2 -m {memory} \
    -drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd \
    -drive if=pflash,format=raw,file=/state/vars.fd \
    -drive file=/state/disk.qcow2,if=virtio,format=qcow2 \
    -netdev user,id=net0,hostfwd=tcp::7443-:7443 -device virtio-net-pci,netdev=net0 \
    -chardev socket,id=tpm,path=/state/swtpm.sock -tpmdev emulator,id=tpm0,chardev=tpm \
    -device tpm-crb,tpmdev=tpm0 \
    -device virtio-rng-pci \
    {user_data}
"#,
        disk = args.disk_size,
        memory = args.memory_mib,
    );
    let mut container = builder
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

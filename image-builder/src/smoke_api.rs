//! The smoke test's checks through the machine's API, what the console cannot show: hctl, built
//! on the host, drives the first boot with a PKI of its own, whose user-data section the test
//! adds to its user-data.

use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context as _, bail, ensure};

use crate::Paths;

/// The probe workload: privileged, the host's `/` at `/host`.
const PROBE: &str = "probe";
const PROBE_IMAGE: &str = "public.ecr.aws/docker/library/busybox:1.37";

/// hctl, configured for the VM's API.
pub struct Hctl {
    binary: PathBuf,
    config_dir: PathBuf,
    endpoint: String,
}

impl Hctl {
    /// Builds hctl and a PKI in `dir`, for the API forwarded to `port`; with the user-data
    /// section enabling the API.
    pub fn prepare(paths: &Paths, dir: &Path, port: u16) -> anyhow::Result<(Self, String)> {
        eprintln!("==> building hctl, and a PKI for the API");
        let manifest = paths.root.join("controllers/Cargo.toml");
        let status = Command::new("cargo")
            .args(["build", "--quiet", "-p", "hctl", "--manifest-path"])
            .arg(&manifest)
            .status()
            .context("running cargo")?;
        ensure!(status.success(), "building hctl failed: {status}");
        if dir.exists() {
            fs::remove_dir_all(dir)?;
        }
        let hctl = Self {
            binary: paths.root.join("controllers/target/debug/hctl"),
            config_dir: dir.to_owned(),
            endpoint: format!("127.0.0.1:{port}"),
        };
        let out = dir.to_str().context("PKI directory")?;
        hctl.succeed(&["pki", "init", "--out", out, "--server-ip", "127.0.0.1"])?;
        let user_data = hctl.succeed(&["pki", "user-data", "--dir", out])?;
        Ok((hctl, user_data))
    }

    /// Runs `hctl args`, `stdin` as its input.
    fn run(&self, args: &[&str], stdin: &str) -> anyhow::Result<Output> {
        let mut child = Command::new(&self.binary)
            .args(args)
            .env("HCTL_CONFIG_DIR", &self.config_dir)
            .env("HCTL_ENDPOINT", &self.endpoint)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("running hctl")?;
        child
            .stdin
            .take()
            .context("hctl's stdin")?
            .write_all(stdin.as_bytes())?;
        Ok(child.wait_with_output()?)
    }

    /// The output of `hctl args`, which must succeed.
    fn succeed(&self, args: &[&str]) -> anyhow::Result<String> {
        let output = self.run(args, "")?;
        ensure!(
            output.status.success(),
            "hctl {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Ok(String::from_utf8(output.stdout)?)
    }

    /// The output of `hctl args` once `ready` accepts it, within `timeout`.
    fn wait(
        &self,
        args: &[&str],
        timeout: Duration,
        ready: impl Fn(&str) -> bool,
    ) -> anyhow::Result<String> {
        let deadline = Instant::now() + timeout;
        loop {
            let last = self.succeed(args);
            if let Ok(output) = &last
                && ready(output)
            {
                return last;
            }
            if Instant::now() > deadline {
                bail!("hctl {}: still {last:?} after {timeout:?}", args.join(" "));
            }
            thread::sleep(Duration::from_secs(2));
        }
    }
}

/// Checks the machine through its API: attestation against the image's expected PCRs, the
/// services, and a privileged workload's exec and read-only host root; then workload-console's
/// exit once idle.
pub fn check(hctl: &Hctl, expected_pcrs: &Path) -> anyhow::Result<()> {
    eprintln!("==> checks through the machine's API");
    hctl.wait(&["version"], Duration::from_secs(120), |_| true)
        .context("the API does not answer")?;

    let expected = expected_pcrs.to_str().context("expected PCRs")?;
    let ek = hctl.succeed(&["attest", "ek"])?;
    let fingerprint = ek
        .lines()
        .find_map(|line| line.strip_prefix("fingerprint: "))
        .context("hctl attest ek printed no fingerprint")?;
    let verified = hctl.succeed(&[
        "attest",
        "verify",
        "--expected",
        expected,
        "--ek",
        fingerprint,
    ])?;
    eprintln!("{verified}");

    let containerd = hctl.succeed(&["service", "status", "containerd"])?;
    ensure!(
        containerd.contains("ready"),
        "containerd is not ready:\n{containerd}"
    );

    hctl.succeed(&[
        "workloads",
        "apply",
        PROBE,
        "--image",
        PROBE_IMAGE,
        "--privileged",
        "--host-root",
        "/host",
        "--",
        "sleep",
        "3600",
    ])?;
    hctl.wait(&["workloads", "list"], Duration::from_secs(180), |list| {
        list.lines()
            .any(|line| line.starts_with(PROBE) && line.contains("running"))
    })
    .context("the probe workload does not run")?;

    let exec = |command: &[&str], stdin: &str| {
        let args: Vec<&str> = ["workloads", "exec", "-i", PROBE, "--"]
            .into_iter()
            .chain(command.iter().copied())
            .collect();
        hctl.run(&args, stdin)
    };
    let exited = exec(&["sh", "-c", "exit 7"], "")?;
    ensure!(
        exited.status.code() == Some(7),
        "exec exited with {}, not 7",
        exited.status
    );
    let echoed = exec(&["cat"], "through the console\n")?;
    ensure!(
        echoed.stdout == b"through the console\n",
        "exec's stdin did not come back: {:?}",
        String::from_utf8_lossy(&echoed.stdout)
    );
    let os_release = exec(&["cat", "/host/usr/lib/os-release"], "")?;
    ensure!(
        String::from_utf8_lossy(&os_release.stdout).contains("hardened"),
        "the host's root is not at /host"
    );
    for path in ["/host/var/probe", "/host/run/probe", "/host/probe"] {
        let written = exec(&["touch", path], "")?;
        ensure!(
            !written.status.success(),
            "{path} is writable: the host's root is not read-only"
        );
    }

    let console = hctl.succeed(&["service", "status", "workload-console"])?;
    ensure!(
        console.contains("ready") || console.contains("running"),
        "workload-console does not run after exec:\n{console}"
    );
    hctl.wait(
        &["service", "status", "workload-console"],
        Duration::from_secs(150),
        |status| status.contains("exited"),
    )
    .context("workload-console does not exit when idle")?;

    hctl.succeed(&["workloads", "rm", PROBE])?;
    eprintln!("==> the API's checks passed");
    Ok(())
}

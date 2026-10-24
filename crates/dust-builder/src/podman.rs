//! The builder image and the containers run from it.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, bail};

use crate::Paths;
use crate::sha256::Sha256;

/// The pinned builder image, tagged by the hash of its Containerfile.
#[derive(Debug, Clone)]
pub struct Builder {
    pub tag: String,
    /// Image ID, part of every cache key and recorded in the SBOM.
    pub id: Sha256,
}

impl Builder {
    pub fn ensure(paths: &Paths) -> anyhow::Result<Self> {
        let dir = paths.root.join("builder");
        let containerfile = Sha256::digest(std::fs::read(dir.join("Containerfile"))?);
        let tag = format!(
            "localhost/hardened-builder:{}",
            hex::encode(containerfile.prefix::<8>())
        );

        let exists = Command::new("podman")
            .args(["image", "exists", &tag])
            .status()
            .context("podman is required")?
            .success();
        if !exists {
            eprintln!("==> building builder image {tag}");
            let status = Command::new("podman")
                .args(["build", "--tag", &tag, "--file"])
                .arg(dir.join("Containerfile"))
                .arg(&dir)
                .status()?;
            if !status.success() {
                bail!("building the builder image failed");
            }
        }

        let output = Command::new("podman")
            .args(["image", "inspect", "--format", "{{.Id}}", &tag])
            .stderr(Stdio::inherit())
            .output()?;
        if !output.status.success() {
            bail!("inspecting the builder image failed");
        }
        let id = String::from_utf8(output.stdout)?
            .trim()
            .parse()
            .context("unexpected builder image ID")?;
        Ok(Self { tag, id })
    }

    /// Prepares a container running `script` with bash.
    pub fn container(&self, script: impl Into<String>) -> Container<'_> {
        Container {
            builder: self,
            script: script.into(),
            mounts: Vec::new(),
            env: Vec::new(),
            network: false,
            devices: Vec::new(),
            ports: Vec::new(),
            interactive: false,
            name: None,
        }
    }
}

/// A bind mount of a host path into the container.
#[derive(Debug)]
struct Mount {
    host: PathBuf,
    guest: String,
    read_only: bool,
}

pub struct Container<'a> {
    builder: &'a Builder,
    script: String,
    mounts: Vec<Mount>,
    env: Vec<(String, String)>,
    network: bool,
    devices: Vec<String>,
    ports: Vec<String>,
    interactive: bool,
    name: Option<String>,
}

impl Container<'_> {
    pub fn mount(self, host: impl AsRef<Path>, guest: impl Into<String>) -> Self {
        self.bind(host, guest, false)
    }

    pub fn mount_ro(self, host: impl AsRef<Path>, guest: impl Into<String>) -> Self {
        self.bind(host, guest, true)
    }

    fn bind(mut self, host: impl AsRef<Path>, guest: impl Into<String>, read_only: bool) -> Self {
        self.mounts.push(Mount {
            host: host.as_ref().to_owned(),
            guest: guest.into(),
            read_only,
        });
        self
    }

    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }

    pub fn network(mut self, enabled: bool) -> Self {
        self.network = enabled;
        self
    }

    pub fn device(mut self, device: impl Into<String>) -> Self {
        self.devices.push(device.into());
        self
    }

    pub fn publish(mut self, port: impl Into<String>) -> Self {
        self.ports.push(port.into());
        self
    }

    /// Names the container, so it can be removed with [`remove`] when its client is killed.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    pub fn command(&self) -> Command {
        let mut cmd = self.run_command();
        cmd.args([&self.builder.tag, "bash", "-euo", "pipefail", "-c", &self.script]);
        cmd
    }

    /// Starts the container in the background, idle, for [`Running::exec`]. It is removed when
    /// the returned handle is dropped.
    pub fn start(&self, name: &str) -> anyhow::Result<Running> {
        remove(name);
        let mut cmd = self.run_command();
        cmd.args(["--detach", "--name", name, &self.builder.tag, "sleep", "infinity"]);
        let status = cmd.stdout(Stdio::null()).status().context("running podman")?;
        if !status.success() {
            bail!("starting container {name} failed with {status}");
        }
        Ok(Running { name: name.to_owned() })
    }

    /// `podman run` with the options, without the image and command.
    fn run_command(&self) -> Command {
        let mut cmd = Command::new("podman");
        cmd.args(["run", "--rm", "--security-opt", "label=disable"]);
        if let Some(name) = &self.name {
            cmd.arg("--name").arg(name);
        }
        if !self.network {
            cmd.args(["--network", "none"]);
        }
        if self.interactive {
            cmd.arg("--interactive");
            if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                cmd.arg("--tty");
            }
        }
        for Mount { host, guest, read_only } in &self.mounts {
            let mode = if *read_only { ":ro" } else { "" };
            cmd.arg("--volume").arg(format!("{}:{guest}{mode}", host.display()));
        }
        for (key, value) in &self.env {
            cmd.arg("--env").arg(format!("{key}={value}"));
        }
        for device in &self.devices {
            cmd.arg("--device").arg(device);
        }
        for port in &self.ports {
            cmd.arg("--publish").arg(port);
        }
        cmd
    }

    pub fn run(&self) -> anyhow::Result<()> {
        let status = self.command().status().context("running podman")?;
        if !status.success() {
            bail!("container exited with {status}");
        }
        Ok(())
    }

    /// Runs the container, returning its standard output.
    pub fn output(&self) -> anyhow::Result<String> {
        let output = self.command().stderr(Stdio::inherit()).output()?;
        if !output.status.success() {
            bail!("container exited with {}", output.status);
        }
        Ok(String::from_utf8(output.stdout)?)
    }
}

/// A container started with [`Container::start`], running commands without a shell.
pub struct Running {
    name: String,
}

impl Running {
    /// Runs `argv` in `dir` with extra environment variables. With `capture`, returns its
    /// standard output; otherwise it goes to the terminal.
    pub fn exec(&self, argv: &[String], dir: &str, env: &[(String, String)], capture: bool) -> anyhow::Result<String> {
        let mut cmd = Command::new("podman");
        cmd.args(["exec", "--workdir", dir]);
        for (key, value) in env {
            cmd.arg("--env").arg(format!("{key}={value}"));
        }
        cmd.arg(&self.name).args(argv);
        if capture {
            let output = cmd.stderr(Stdio::inherit()).output().context("running podman")?;
            if !output.status.success() {
                bail!("{} failed with {}", argv[0], output.status);
            }
            Ok(String::from_utf8(output.stdout)?)
        } else {
            let status = cmd.status().context("running podman")?;
            if !status.success() {
                bail!("{} failed with {status}", argv[0]);
            }
            Ok(String::new())
        }
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        remove(&self.name);
    }
}

/// Force-removes a named container (stopping it first).
pub fn remove(name: &str) {
    let _ = Command::new("podman")
        .args(["rm", "--force", "--time", "0", name])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

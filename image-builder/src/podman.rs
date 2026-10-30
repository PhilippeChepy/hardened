//! Environment images (see [`crate::environment`]) and the containers run from them.

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, ensure};

use crate::sha256::Sha256;

/// The image of an environment.
#[derive(Debug, Clone)]
pub struct Image {
    pub tag: String,
    /// What the image is built from (see [`crate::environment::ensure`]), part of the cache keys
    /// of the components built in it.
    pub key: Sha256,
}

impl Image {
    /// Prepares a container of the image.
    pub fn container(&self) -> Container<'_> {
        Container {
            image: self,
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

/// Whether the image `tag` exists locally.
pub fn exists(tag: &str) -> anyhow::Result<bool> {
    Ok(Command::new("podman")
        .args(["image", "exists", tag])
        .status()
        .context("podman is required")?
        .success())
}

/// Builds `containerfile` with `context`, as `tag`, with named build contexts (for
/// `COPY --from=<name>`), its output going to the file `log`. The image is one layer: environments
/// copy many component trees.
pub fn build(
    containerfile: &Path,
    context: &Path,
    tag: &str,
    contexts: &[(String, PathBuf)],
    log: &Path,
) -> anyhow::Result<()> {
    if let Some(dir) = log.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let output = File::create(log)?;
    let mut cmd = Command::new("podman");
    cmd.args(["build", "--tag", tag, "--file"])
        .arg(containerfile)
        .arg("--squash-all");
    for (name, path) in contexts {
        cmd.arg("--build-context")
            .arg(format!("{name}={}", path.display()));
    }
    let status = cmd
        .arg(context)
        .stdout(output.try_clone()?)
        .stderr(output)
        .status()
        .context("running podman")?;
    ensure!(
        status.success(),
        "podman build failed with {status} (log: {})",
        log.display()
    );
    Ok(())
}

/// A bind mount of a host path into the container.
#[derive(Debug)]
struct Mount {
    host: PathBuf,
    guest: String,
    read_only: bool,
}

/// A container being prepared: it runs a shell script ([`Container::run`]), or commands without
/// a shell ([`Container::start`]).
pub struct Container<'a> {
    image: &'a Image,
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

    /// Attaches the terminal (stdin, and a TTY when there is one).
    pub fn interactive(mut self) -> Self {
        self.interactive = true;
        self
    }

    /// The `podman run` command running `script` with `sh -eu` (POSIX: the seed has no bash).
    pub fn command(&self, script: &str) -> Command {
        let mut cmd = self.run_command();
        cmd.args([&self.image.tag, "sh", "-eu", "-c", script]);
        cmd
    }

    /// Starts the container in the background, idle, for [`Running::exec`], whose commands write
    /// their output to `log`. It is removed when the returned handle is dropped.
    pub fn start(&self, name: &str, log: &File) -> anyhow::Result<Running> {
        remove(name);
        let mut cmd = self.run_command();
        cmd.args([
            "--detach",
            "--name",
            name,
            &self.image.tag,
            "sleep",
            "infinity",
        ]);
        let status = cmd
            .stdout(Stdio::null())
            .status()
            .context("running podman")?;
        ensure!(
            status.success(),
            "starting container {name} failed with {status}"
        );
        Ok(Running {
            name: name.to_owned(),
            log: log.try_clone()?,
        })
    }

    /// `podman run` with the options, without the image and command.
    fn run_command(&self) -> Command {
        let mut cmd = Command::new("podman");
        // Environments built from scratch have no /tmp.
        cmd.args([
            "run",
            "--rm",
            "--security-opt",
            "label=disable",
            "--tmpfs",
            "/tmp:rw,exec,mode=1777",
        ]);
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
        for Mount {
            host,
            guest,
            read_only,
        } in &self.mounts
        {
            let mode = if *read_only { ":ro" } else { "" };
            cmd.arg("--volume")
                .arg(format!("{}:{guest}{mode}", host.display()));
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

    /// Runs `script` in the container.
    pub fn run(&self, script: &str) -> anyhow::Result<()> {
        let status = self.command(script).status().context("running podman")?;
        ensure!(status.success(), "container exited with {status}");
        Ok(())
    }

    /// Runs `script` in the container, returning its standard output.
    pub fn output(&self, script: &str) -> anyhow::Result<String> {
        let output = self.command(script).stderr(Stdio::inherit()).output()?;
        ensure!(
            output.status.success(),
            "container exited with {}",
            output.status
        );
        Ok(String::from_utf8(output.stdout)?)
    }
}

/// A container started with [`Container::start`], running commands without a shell.
pub struct Running {
    name: String,
    log: File,
}

impl Running {
    /// Runs `argv` in `dir` with extra environment variables, its output going to the log.
    pub fn exec(&self, argv: &[String], dir: &str, env: &[(String, String)]) -> anyhow::Result<()> {
        let status = (self.command(argv, dir, env)?)
            .stdout(self.log.try_clone()?)
            .status()
            .context("running podman")?;
        ensure!(status.success(), "{} failed with {status}", argv[0]);
        Ok(())
    }

    /// Runs `argv` like [`Running::exec`], returning its standard output.
    pub fn capture(
        &self,
        argv: &[String],
        dir: &str,
        env: &[(String, String)],
    ) -> anyhow::Result<String> {
        let output = (self.command(argv, dir, env)?)
            .output()
            .context("running podman")?;
        ensure!(
            output.status.success(),
            "{} failed with {}",
            argv[0],
            output.status
        );
        Ok(String::from_utf8(output.stdout)?)
    }

    /// `podman exec` of `argv`, its standard error going to the log.
    fn command(
        &self,
        argv: &[String],
        dir: &str,
        env: &[(String, String)],
    ) -> anyhow::Result<Command> {
        let mut cmd = Command::new("podman");
        cmd.args(["exec", "--workdir", dir]);
        for (key, value) in env {
            cmd.arg("--env").arg(format!("{key}={value}"));
        }
        cmd.arg(&self.name).args(argv).stderr(self.log.try_clone()?);
        Ok(cmd)
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

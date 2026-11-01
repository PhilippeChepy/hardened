//! A workload as a service of serviced, in containerd's `system` namespace (Kubernetes' pods are
//! in CRI's, `k8s.io`): `ctr images pull` for its image, with the registry hosts machine-controller
//! writes from `settings.container-registry`, then `ctr run` in the foreground, which serviced
//! supervises like any process: the container's exit code is the service's, and SIGTERM, then
//! SIGKILL, are forwarded to the container.
//!
//! The workload is kept in the service's `meta.workload`, from which [`to_workload`] reads it
//! back.

use std::collections::BTreeMap;

use controllers_helpers::WorkloadName;
use libserviced::definition;
use libserviced::definition::AbsolutePath;
use libserviced::definition::Command;
use libserviced::definition::Condition;
use libserviced::definition::Restart;
use libserviced::definition::Service;
use libserviced::definition::ServiceName;
use workload_controller::ImageWorkload;
use workload_controller::Privileges;
use workload_controller::RestartPolicy;

/// The containerd namespace of workloads, apart from Kubernetes'.
const NAMESPACE: &str = "system";
/// Where machine-controller writes the registries' `hosts.toml` files (containerd's
/// `config_path`): `ctr` reads them itself, containerd's configuration only applies to CRI.
const HOSTS_DIR: &str = "/run/containerd/certs.d";
const CTR: AbsolutePath = AbsolutePath::from_static("/usr/bin/ctr");
const CONTAINERD: ServiceName = ServiceName::from_static("containerd");

/// Why a workload's service file cannot be written: what its parsing already excludes (a NUL
/// byte in an argument, a mount source not absolute), or TOML failing to serialize it.
#[derive(Debug, thiserror::Error)]
pub enum ServiceFileError {
    /// serviced's definitions refused a value.
    #[error(transparent)]
    Definition(#[from] definition::Error),
    /// The service did not serialize.
    #[error("serializing the service: {0}")]
    Toml(#[from] toml::ser::Error),
}

/// `ctr` with `args`, which come from a workload, checked when it was parsed.
fn ctr(args: impl IntoIterator<Item = impl Into<String>>) -> Result<Command, definition::Error> {
    Command::new(CTR, args)
}

/// The service running `workload`.
fn to_service(name: &WorkloadName, workload: &ImageWorkload) -> Result<Service, ServiceFileError> {
    let id = name.container_id().to_owned();
    let image = workload.image.as_str();
    let namespaced = |args: &[&str]| {
        let args = ["--namespace", NAMESPACE].iter().chain(args);
        ctr(args.copied()).map(Command::ignore_failure)
    };
    // What a run stopped abruptly (SIGKILL) left behind; `--rm` removes the rest. A container
    // record also survives a crash of the machine (tasks do not: their state is in /run).
    let delete_container = namespaced(&["containers", "delete", &id])?;
    let cleanup = vec![
        namespaced(&["tasks", "delete", "--force", &id])?,
        delete_container.clone(),
    ];
    // Unpacked by ctr itself (`--local`), synced to disk: the transfer service's unpack does
    // not sync, and a power loss after a pull would leave a kept image with empty files. Only
    // this platform's manifests are fetched (`--skip-metadata`): registries rate-limit requests.
    let pull = [
        "--namespace",
        NAMESPACE,
        "images",
        "pull",
        "--local",
        "--sync-fs",
        "--skip-metadata",
        "--hosts-dir",
        HOSTS_DIR,
        image,
    ];

    let mut run: Vec<String> = ["--namespace", NAMESPACE, "run", "--rm", "--net-host"]
        .map(String::from)
        .into();
    if let Privileges::Privileged { host_root } = &workload.privileged {
        run.push("--privileged".into());
        // `rro`: read-only submounts too (`/var`, `/run`), which `ro` would leave writable.
        if let Some(host_root) = host_root {
            run.extend([
                "--mount".into(),
                format!("type=bind,src=/,dst={host_root},options=rbind:rro"),
            ]);
        }
    }
    for (name, value) in &workload.env {
        run.extend(["--env".into(), format!("{name}={value}")]);
    }
    for mount in &workload.mounts {
        let mode = if mount.read_only { "ro" } else { "rw" };
        run.extend([
            "--mount".into(),
            format!(
                "type=bind,src={},dst={},options=rbind:{mode}",
                mount.source, mount.destination
            ),
        ]);
    }
    run.extend([image.to_owned(), id]);
    // `ctr run` replaces the image's whole process (entrypoint and command) with what follows the
    // ID: the whole command line.
    run.extend(workload.command.iter().cloned().map(String::from));

    let mut meta = toml::Table::new();
    meta.insert("workload".into(), toml::Value::try_from(workload)?);
    // Bind mount sources must exist.
    let runtime_directories = workload
        .mounts
        .iter()
        .map(|mount| mount.source.as_str().parse())
        .collect::<Result<_, _>>()?;
    Ok(Service {
        description: format!("workload {name}: {image}"),
        enabled: true,
        sockets: Vec::new(),
        exec: ctr(run)?,
        exec_pre: vec![delete_container, ctr(pull)?],
        exec_post: cleanup,
        exec_stop: Vec::new(),
        restart: match workload.restart {
            RestartPolicy::Always => Restart::Always,
            RestartPolicy::OnFailure => Restart::OnFailure,
            RestartPolicy::Never => Restart::Never,
        },
        requires: vec![CONTAINERD],
        condition: Condition::default(),
        notify: false,
        oneshot: false,
        env: BTreeMap::new(),
        runtime_directories,
        console: workload.console,
        api: Vec::new(),
        sandbox: None,
        meta,
    })
}

/// The service file running `workload`.
///
/// # Errors
///
/// When its parsing let through what serviced refuses, or it does not serialize.
pub fn to_toml(name: &WorkloadName, workload: &ImageWorkload) -> Result<String, ServiceFileError> {
    Ok(toml::to_string(&to_service(name, workload)?)?)
}

/// The workload a service runs, from its `meta.workload`; `None` for other services.
#[must_use]
pub fn to_workload(service: &Service) -> Option<ImageWorkload> {
    service.meta.get("workload")?.clone().try_into().ok()
}

#[cfg(test)]
pub(crate) mod tests {
    use workload_controller::ContainerSettings;
    use workload_controller::workloads;

    use super::*;

    /// The workload `name` of user-data, running [`workload`].
    pub(crate) fn declared(name: &str, enabled: bool) -> workloads::DeclaredWorkload {
        ContainerSettings {
            enabled,
            workload: workload(),
        }
        .into_proto(name.parse().unwrap())
    }

    pub(crate) fn workload() -> ImageWorkload {
        toml::from_str(
            r#"
image = "busybox:1.37"
command = ["sh", "-c", "echo hi"]
env = { A = "1 2" }
privileged.host-root = "/host"
restart = "on-failure"
mounts = [{ source = "/var/lib/web", destination = "/data", read-only = true }]
console = true
"#,
        )
        .unwrap()
    }

    #[test]
    fn runs_the_workload_with_ctr() {
        let service = to_service(&"web".parse().unwrap(), &workload()).unwrap();
        assert_eq!(
            Vec::from(service.exec.clone()),
            [
                "/usr/bin/ctr",
                "--namespace",
                "system",
                "run",
                "--rm",
                "--net-host",
                "--privileged",
                "--mount",
                "type=bind,src=/,dst=/host,options=rbind:rro",
                "--env",
                "A=1 2",
                "--mount",
                "type=bind,src=/var/lib/web,dst=/data,options=rbind:ro",
                "docker.io/library/busybox:1.37",
                "workload-web",
                "sh",
                "-c",
                "echo hi",
            ]
        );
        assert_eq!(
            Vec::from(service.exec_pre[0].clone()),
            [
                "-/usr/bin/ctr",
                "--namespace",
                "system",
                "containers",
                "delete",
                "workload-web"
            ]
        );
        assert_eq!(
            Vec::from(service.exec_pre[1].clone()),
            [
                "/usr/bin/ctr",
                "--namespace",
                "system",
                "images",
                "pull",
                "--local",
                "--sync-fs",
                "--skip-metadata",
                "--hosts-dir",
                "/run/containerd/certs.d",
                "docker.io/library/busybox:1.37",
            ]
        );
        assert!(!service.exec_pre[1].may_fail());
        assert!(service.exec_post.iter().all(Command::may_fail));
        assert_eq!(service.restart, Restart::OnFailure);
        assert_eq!(service.requires[0].as_str(), "containerd");
        assert_eq!(service.runtime_directories[0].as_str(), "/var/lib/web");
        assert!(service.console);
    }

    #[test]
    fn the_workload_round_trips_through_the_service_file() {
        let text = to_toml(&"web".parse().unwrap(), &workload()).unwrap();
        let back: Service = toml::from_str(&text).unwrap();
        assert_eq!(to_workload(&back), Some(workload()));
        assert_eq!(
            to_workload(&Service {
                meta: toml::Table::new(),
                ..back
            }),
            None
        );
    }
}

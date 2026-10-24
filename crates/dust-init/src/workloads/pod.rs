//! CRI requests of a workload: one pod sandbox holding one container.
//!
//! The runtime builds the OCI spec from these. Every pod shares the host network namespace (no
//! CNI) and its IPC namespace with the pod's pause process; each container has its own pid
//! namespace and runs under the `/hardened/<name>` cgroup.

use std::collections::HashMap;
use std::path::Path;

use cri_api::v1::{
    ContainerConfig, ContainerMetadata, ImageSpec, KeyValue, LinuxContainerConfig, LinuxContainerSecurityContext,
    LinuxPodSandboxConfig, LinuxSandboxSecurityContext, Mount, NamespaceMode, NamespaceOption, PodSandboxConfig,
    PodSandboxMetadata, SecurityProfile, security_profile::ProfileType,
};

use super::BindMount;
use super::cri::ImageId;
use crate::settings::ImageWorkload;
use crate::types::WorkloadName;

/// Pod namespace of every workload (CRI metadata, not a Linux namespace).
pub const POD_NAMESPACE: &str = "hardened";
/// Label naming the workload of a sandbox or container.
pub const WORKLOAD_LABEL: &str = "io.hardened.workload";

/// Host files shared read-only with image workloads, when present: they are kept up to date
/// by dust-init, unlike the runtime's copies.
pub const HOST_FILES: &[(&str, &str)] = &[
    ("/run/hardened/resolv.conf", "/etc/resolv.conf"),
    ("/run/hardened/hosts", "/etc/hosts"),
];

/// Kubernetes' default masked paths: containerd applies none unless asked.
const MASKED_PATHS: &[&str] = &[
    "/proc/asound",
    "/proc/acpi",
    "/proc/interrupts",
    "/proc/kcore",
    "/proc/keys",
    "/proc/latency_stats",
    "/proc/timer_list",
    "/proc/timer_stats",
    "/proc/sched_debug",
    "/proc/scsi",
    "/sys/firmware",
    "/sys/devices/virtual/powercap",
];

const READONLY_PATHS: &[&str] = &["/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger"];

/// One run of a workload: what identifies its pod and where its log goes.
#[derive(Debug, Clone)]
pub struct Run<'a> {
    pub name: &'a WorkloadName,
    /// Identifies the workload's incarnation: stable across its restarts.
    pub uid: &'a str,
    /// Runs of this incarnation so far.
    pub attempt: u32,
    /// The pod's log directory.
    pub log_directory: &'a Path,
}

/// The container log of workload `name`, relative to its pod's log directory.
pub fn log_file(name: &WorkloadName) -> String {
    format!("{name}.log")
}

/// The labels of the sandbox and container of workload `name`, which also select them.
pub fn workload_selector(name: &WorkloadName) -> HashMap<String, String> {
    HashMap::from([(WORKLOAD_LABEL.to_owned(), name.to_string())])
}

pub fn sandbox_config(run: &Run<'_>, workload: &ImageWorkload) -> PodSandboxConfig {
    let privileged = workload.privileged;
    PodSandboxConfig {
        metadata: Some(PodSandboxMetadata {
            name: run.name.to_string(),
            uid: run.uid.to_owned(),
            namespace: POD_NAMESPACE.to_owned(),
            attempt: run.attempt,
        }),
        // The pod shares the host's UTS namespace with its network one: the runtime refuses a
        // hostname, and containers see the machine's.
        hostname: String::new(),
        log_directory: run.log_directory.to_string_lossy().into_owned(),
        labels: workload_selector(run.name),
        linux: Some(LinuxPodSandboxConfig {
            cgroup_parent: format!("/hardened/{}", run.name),
            security_context: Some(LinuxSandboxSecurityContext {
                namespace_options: Some(namespaces()),
                // A privileged container needs a privileged sandbox.
                privileged,
                seccomp: Some(seccomp(privileged)),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// The container of an image workload. `image` is the resolved `workload.image`;
/// `host_files` are the present [`HOST_FILES`].
pub fn image_container(
    run: &Run<'_>,
    workload: &ImageWorkload,
    image: &ImageId,
    host_files: &[BindMount],
) -> ContainerConfig {
    let mut mounts: Vec<Mount> = host_files.iter().map(mount).collect();
    mounts.extend(workload.mounts.iter().map(|m| Mount {
        container_path: m.destination.to_string(),
        host_path: m.source.to_string(),
        readonly: m.read_only,
        ..Default::default()
    }));
    let security_context = if workload.privileged {
        LinuxContainerSecurityContext {
            privileged: true,
            namespace_options: Some(namespaces()),
            seccomp: Some(seccomp(true)),
            ..Default::default()
        }
    } else {
        LinuxContainerSecurityContext {
            // The runtime's default capability set.
            capabilities: None,
            ..confined()
        }
    };
    ContainerConfig {
        // Docker semantics, which CRI follows: `command` replaces the entrypoint (and drops the
        // image's command), `args` replaces the image's command.
        command: workload.command.clone(),
        args: workload.args.clone(),
        envs: envs(workload.env.iter().map(|(k, v)| (k.as_str(), v.as_str()))),
        mounts,
        linux: Some(LinuxContainerConfig {
            resources: None,
            security_context: Some(security_context),
        }),
        ..container(run, workload.image.as_str(), image)
    }
}

/// The fields common to every container.
fn container(run: &Run<'_>, reference: &str, image: &ImageId) -> ContainerConfig {
    ContainerConfig {
        metadata: Some(ContainerMetadata {
            name: run.name.to_string(),
            attempt: run.attempt,
        }),
        image: Some(ImageSpec {
            image: image.as_str().to_owned(),
            user_specified_image: reference.to_owned(),
            ..Default::default()
        }),
        labels: workload_selector(run.name),
        log_path: log_file(run.name),
        ..Default::default()
    }
}

/// Confinement of unprivileged containers: the runtime's default seccomp profile and
/// capabilities, no privilege escalation, masked kernel interfaces.
fn confined() -> LinuxContainerSecurityContext {
    LinuxContainerSecurityContext {
        namespace_options: Some(namespaces()),
        no_new_privs: true,
        masked_paths: MASKED_PATHS.iter().map(|&p| p.to_owned()).collect(),
        readonly_paths: READONLY_PATHS.iter().map(|&p| p.to_owned()).collect(),
        seccomp: Some(seccomp(false)),
        ..Default::default()
    }
}

/// Host network; a pid namespace per container; IPC shared within the pod.
fn namespaces() -> NamespaceOption {
    NamespaceOption {
        network: NamespaceMode::Node.into(),
        pid: NamespaceMode::Container.into(),
        ipc: NamespaceMode::Pod.into(),
        ..Default::default()
    }
}

fn seccomp(privileged: bool) -> SecurityProfile {
    SecurityProfile {
        profile_type: if privileged {
            ProfileType::Unconfined
        } else {
            ProfileType::RuntimeDefault
        }
        .into(),
        localhost_ref: String::new(),
    }
}

fn mount(bind: &BindMount) -> Mount {
    Mount {
        container_path: bind.destination.to_string(),
        host_path: bind.source.to_string(),
        readonly: bind.read_only,
        ..Default::default()
    }
}

fn envs<'a>(env: impl Iterator<Item = (&'a str, &'a str)>) -> Vec<KeyValue> {
    env.map(|(key, value)| KeyValue {
        key: key.to_owned(),
        value: value.as_bytes().to_vec(),
    })
    .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::settings::{MountSettings, RestartPolicy};

    fn parse<T: std::str::FromStr>(s: &str) -> T
    where
        T::Err: std::fmt::Debug,
    {
        s.parse().unwrap()
    }

    fn nginx() -> ImageWorkload {
        ImageWorkload {
            image: parse("nginx:1.29"),
            command: Vec::new(),
            args: Vec::new(),
            env: BTreeMap::from([(parse("A"), "1".to_owned())]),
            privileged: false,
            restart: RestartPolicy::Always,
            mounts: vec![MountSettings {
                source: parse("/var/lib/web"),
                destination: parse("/data"),
                read_only: true,
            }],
            console: false,
        }
    }

    fn image_id() -> ImageId {
        ImageId::from(format!("sha256:{}", "a".repeat(64)))
    }

    fn with_run<T>(name: &str, f: impl FnOnce(&Run<'_>) -> T) -> T {
        let name: WorkloadName = parse(name);
        let log_directory = Path::new("/var/log/pods").join(name.as_str());
        f(&Run {
            name: &name,
            uid: "6f1c2a51-6e1a-4e43-9b0b-0d8c3f0b6a2e",
            attempt: 2,
            log_directory: &log_directory,
        })
    }

    fn security(config: &ContainerConfig) -> &LinuxContainerSecurityContext {
        config.linux.as_ref().unwrap().security_context.as_ref().unwrap()
    }

    fn host_network(options: &NamespaceOption) {
        assert_eq!(options.network, i32::from(NamespaceMode::Node));
        assert_eq!(options.pid, i32::from(NamespaceMode::Container));
        assert_eq!(options.ipc, i32::from(NamespaceMode::Pod));
    }

    #[test]
    fn sandboxes_identify_their_workload() {
        let config = with_run("web", |run| sandbox_config(run, &nginx()));
        let metadata = config.metadata.as_ref().unwrap();
        assert_eq!(metadata.name, "web");
        assert_eq!(metadata.namespace, POD_NAMESPACE);
        assert_eq!(metadata.uid, "6f1c2a51-6e1a-4e43-9b0b-0d8c3f0b6a2e");
        assert_eq!(metadata.attempt, 2);
        assert_eq!(config.hostname, "");
        assert_eq!(config.log_directory, "/var/log/pods/web");
        assert_eq!(config.labels, workload_selector(&parse("web")));
        assert!(config.dns_config.is_none());

        let linux = config.linux.as_ref().unwrap();
        assert_eq!(linux.cgroup_parent, "/hardened/web");
        let security = linux.security_context.as_ref().unwrap();
        host_network(security.namespace_options.as_ref().unwrap());
        assert!(!security.privileged);
        assert_eq!(
            security.seccomp.as_ref().unwrap().profile_type,
            i32::from(ProfileType::RuntimeDefault)
        );

        let mut privileged = nginx();
        privileged.privileged = true;
        let config = with_run("web", |run| sandbox_config(run, &privileged));
        let security = config.linux.unwrap().security_context.unwrap();
        assert!(security.privileged);
        assert_eq!(
            security.seccomp.unwrap().profile_type,
            i32::from(ProfileType::Unconfined)
        );
    }

    #[test]
    fn image_containers_are_confined() {
        let host_files = [BindMount {
            source: parse("/run/hardened/resolv.conf"),
            destination: parse("/etc/resolv.conf"),
            read_only: true,
        }];
        let config = with_run("web", |run| image_container(run, &nginx(), &image_id(), &host_files));

        assert_eq!(config.metadata.as_ref().unwrap().name, "web");
        assert_eq!(config.metadata.as_ref().unwrap().attempt, 2);
        let image = config.image.as_ref().unwrap();
        assert_eq!(image.image, image_id().as_str());
        assert_eq!(image.user_specified_image, "docker.io/library/nginx:1.29");
        assert_eq!(config.log_path, "web.log");
        assert_eq!(config.labels[WORKLOAD_LABEL], "web");
        assert_eq!(
            config.envs,
            [KeyValue {
                key: "A".into(),
                value: b"1".to_vec()
            }]
        );
        assert!(!config.tty && !config.stdin);

        let mounts: Vec<(&str, &str, bool)> = config
            .mounts
            .iter()
            .map(|m| (m.host_path.as_str(), m.container_path.as_str(), m.readonly))
            .collect();
        assert_eq!(
            mounts,
            [
                ("/run/hardened/resolv.conf", "/etc/resolv.conf", true),
                ("/var/lib/web", "/data", true)
            ]
        );

        let security = security(&config);
        assert!(!security.privileged);
        assert!(security.no_new_privs);
        assert!(security.capabilities.is_none());
        assert!(security.run_as_user.is_none(), "the image's user applies");
        assert!(!security.readonly_rootfs);
        assert_eq!(
            security.seccomp.as_ref().unwrap().profile_type,
            i32::from(ProfileType::RuntimeDefault)
        );
        assert!(security.masked_paths.iter().any(|p| p == "/proc/kcore"));
        assert!(security.readonly_paths.iter().any(|p| p == "/proc/sys"));
        host_network(security.namespace_options.as_ref().unwrap());
    }

    #[test]
    fn privileged_image_containers_are_unconfined() {
        let mut workload = nginx();
        workload.privileged = true;
        let config = with_run("x", |run| image_container(run, &workload, &image_id(), &[]));
        let security = security(&config);
        assert!(security.privileged);
        assert!(!security.no_new_privs);
        assert!(security.masked_paths.is_empty());
        assert!(security.readonly_paths.is_empty());
        assert_eq!(
            security.seccomp.as_ref().unwrap().profile_type,
            i32::from(ProfileType::Unconfined)
        );
        host_network(security.namespace_options.as_ref().unwrap());
    }

    #[test]
    fn commands_map_to_cri_like_docker() {
        let config = |command: &[&str], args: &[&str]| {
            let mut workload = nginx();
            workload.command = command.iter().map(|&s| s.into()).collect();
            workload.args = args.iter().map(|&s| s.into()).collect();
            with_run("x", |run| image_container(run, &workload, &image_id(), &[]))
        };
        // Nothing set: the runtime runs the image's entrypoint and command.
        let c = config(&[], &[]);
        assert!(c.command.is_empty() && c.args.is_empty());
        // `args` only: the image's entrypoint with these arguments.
        let c = config(&[], &["nginx-debug"]);
        assert!(c.command.is_empty());
        assert_eq!(c.args, ["nginx-debug"]);
        // `command`: replaces the entrypoint and drops the image's command.
        let c = config(&["/bin/sh", "-c"], &[]);
        assert_eq!(c.command, ["/bin/sh", "-c"]);
        assert!(c.args.is_empty());
        let c = config(&["/bin/sh", "-c"], &["echo hi"]);
        assert_eq!(
            (c.command.as_slice(), c.args.as_slice()),
            (&["/bin/sh".to_owned(), "-c".into()][..], &["echo hi".to_owned()][..])
        );
    }
}

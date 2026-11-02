//! NVIDIA's Kubernetes plugins as workloads of the variant: their images are in its root
//! filesystem, glibc's programs (they load NVML), privileged. The host's root is at `/host`, read
//! only: the driver root (its user space) is found there, and the CDI specs they write name its
//! host path. They write those specs in `/var/lib/cdi`, which CRI reads (the variant's containerd
//! drop-in); their hooks are `/usr/bin/nvidia-cdi-hook`, which runc runs on the host.

use std::str::FromStr;

use controllers_helpers::InvalidValue;
use controllers_helpers::WorkloadName;
use workload_controller::ImageWorkload;
use workload_controller::MountSettings;
use workload_controller::Privileges;
use workload_controller::RestartPolicy;

use crate::DeviceIdStrategy;
use crate::DevicePartitioningStrategy;
use crate::DevicePluginSettings;
use crate::DeviceSharingStrategy;

/// The device plugin's version, its image's tag (the variant's `nvidia-k8s-device-plugin`).
pub const DEVICE_PLUGIN_VERSION: &str = "0.20.1";
/// The DRA driver's version, its kubelet plugin's image's tag (`nvidia-dra-kubelet-plugin`).
pub const DRA_VERSION: &str = "0.5.1";
/// Where the device plugin's time-slicing configuration is, on the host (written by
/// machine-controller) and in its container.
pub const DEVICE_PLUGIN_CONFIG_DIR: &str = "/var/lib/nvidia-device-plugin";
/// The CDI specs CRI reads.
const CDI_DIR: &str = "/var/lib/cdi";
const HOST_ROOT: &str = "/host";
const CDI_HOOK: &str = "/usr/bin/nvidia-cdi-hook";

/// The device plugin's workload, with the driver of `driver_version`.
///
/// # Errors
///
/// Never with the variant's constants: they are checked as any workload's values are.
pub fn device_plugin(
    settings: &DevicePluginSettings,
    driver_version: &str,
) -> Result<(WorkloadName, ImageWorkload), InvalidValue> {
    let driver_root = driver_root(driver_version);
    let mut command = vec![
        "/usr/bin/nvidia-device-plugin".to_owned(),
        format!("--driver-root={driver_root}"),
        format!("--driver-root-ctr-path={HOST_ROOT}{driver_root}"),
        "--dev-root=/".to_owned(),
        format!("--nvidia-cdi-hook-path={CDI_HOOK}"),
        format!("--pass-device-specs={}", settings.pass_device_specs),
        format!(
            "--device-id-strategy={}",
            match settings.device_id_strategy {
                DeviceIdStrategy::Index => "index",
                DeviceIdStrategy::Uuid => "uuid",
            }
        ),
        format!("--device-list-strategy={}", settings.plugin_list_strategy()),
        // MIG instances as nvidia.com/gpu, as Bottlerocket advertises them.
        format!(
            "--mig-strategy={}",
            match settings.device_partitioning_strategy {
                DevicePartitioningStrategy::None => "none",
                DevicePartitioningStrategy::Mig => "single",
            }
        ),
    ];
    let mut mounts = vec![
        mount(
            "/var/lib/kubelet/device-plugins",
            "/var/lib/kubelet/device-plugins",
            false,
        )?,
        mount(CDI_DIR, "/var/run/cdi", false)?,
    ];
    if time_slicing_config(settings).is_some() {
        command.push("--config-file=/config/config.yaml".to_owned());
        mounts.push(mount(DEVICE_PLUGIN_CONFIG_DIR, "/config", true)?);
    }
    workload(
        "nvidia-device-plugin",
        "nvidia-device-plugin",
        DEVICE_PLUGIN_VERSION,
        command,
        mounts,
    )
}

/// The device plugin's configuration file for time-slicing, if it shares the GPUs.
#[must_use]
pub fn time_slicing_config(settings: &DevicePluginSettings) -> Option<String> {
    if settings.device_sharing_strategy != DeviceSharingStrategy::TimeSlicing {
        return None;
    }
    let slicing = settings.time_slicing;
    Some(format!(
        "version: v1\nsharing:\n  timeSlicing:\n    renameByDefault: {}\n    \
         failRequestsGreaterThanOne: {}\n    resources:\n      - name: nvidia.com/gpu\n        \
         replicas: {}\n",
        slicing.rename_by_default, slicing.fail_requests_greater_than_one, slicing.replicas
    ))
}

/// The DRA driver's kubelet plugin's workload on the node `node_name`, with the driver of
/// `driver_version`. It publishes the node's GPUs with the node's credentials (kubelet's
/// kubeconfig, its client certificate in `/var/lib/kubelet`).
///
/// # Errors
///
/// Never with the variant's constants: they are checked as any workload's values are.
pub fn dra_kubelet_plugin(
    node_name: &str,
    driver_version: &str,
) -> Result<(WorkloadName, ImageWorkload), InvalidValue> {
    let driver_root = driver_root(driver_version);
    let command = vec![
        "/usr/bin/gpu-kubelet-plugin".to_owned(),
        format!("--node-name={node_name}"),
        format!("--kubeconfig={HOST_ROOT}/run/kubelet/kubeconfig"),
        format!("--nvidia-driver-root={driver_root}"),
        format!("--container-driver-root={HOST_ROOT}{driver_root}"),
        format!("--host-root={HOST_ROOT}"),
        "--cdi-root=/var/run/cdi".to_owned(),
        format!("--nvidia-cdi-hook-path={CDI_HOOK}"),
        "--kubelet-plugins-directory-path=/var/lib/kubelet/plugins".to_owned(),
        "--kubelet-registrar-directory-path=/var/lib/kubelet/plugins_registry".to_owned(),
    ];
    let mounts = vec![
        mount("/var/lib/kubelet", "/var/lib/kubelet", false)?,
        mount(CDI_DIR, "/var/run/cdi", false)?,
    ];
    workload(
        "nvidia-dra-kubelet-plugin",
        "nvidia-dra-kubelet-plugin",
        DRA_VERSION,
        command,
        mounts,
    )
}

/// The driver's user space, on the host.
#[must_use]
fn driver_root(driver_version: &str) -> String {
    format!("/usr/lib/nvidia/{driver_version}/root")
}

fn mount(source: &str, destination: &str, read_only: bool) -> Result<MountSettings, InvalidValue> {
    Ok(MountSettings {
        source: source.parse()?,
        destination: destination.parse()?,
        read_only,
    })
}

fn workload(
    name: &str,
    image: &str,
    version: &str,
    command: Vec<String>,
    mounts: Vec<MountSettings>,
) -> Result<(WorkloadName, ImageWorkload), InvalidValue> {
    let workload = ImageWorkload {
        image: format!("localhost/hardened/{image}:{version}").parse()?,
        command: (command.into_iter())
            .map(|argument| argument.parse())
            .collect::<Result<_, _>>()?,
        env: Default::default(),
        privileged: Privileges::Privileged {
            host_root: Some(HOST_ROOT.parse()?),
        },
        restart: RestartPolicy::Always,
        mounts,
        console: false,
    };
    Ok((WorkloadName::from_str(name)?, workload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_device_plugin_with_the_driver_root_and_cdi() {
        let (name, workload) =
            device_plugin(&DevicePluginSettings::default(), "595.112.07").unwrap();
        assert_eq!(name.as_str(), "nvidia-device-plugin");
        assert_eq!(
            workload.image.as_str(),
            "localhost/hardened/nvidia-device-plugin:0.20.1"
        );
        let command: Vec<&str> = workload.command.iter().map(|a| a.as_str()).collect();
        assert!(command.contains(&"--driver-root-ctr-path=/host/usr/lib/nvidia/595.112.07/root"));
        assert!(command.contains(&"--device-list-strategy=cdi-cri"));
        assert!(command.contains(&"--mig-strategy=none"));
        assert!(!command.iter().any(|a| a.starts_with("--config-file")));
        assert_eq!(workload.mounts.len(), 2);
        assert!(workload.privileged.is_privileged());
    }

    #[test]
    fn mig_instances_as_gpus() {
        let settings = DevicePluginSettings {
            device_partitioning_strategy: DevicePartitioningStrategy::Mig,
            ..DevicePluginSettings::default()
        };
        let (_, workload) = device_plugin(&settings, "595.112.07").unwrap();
        assert!(
            workload
                .command
                .iter()
                .any(|a| a.as_str() == "--mig-strategy=single")
        );
    }

    #[test]
    fn time_slicing_through_a_configuration_file() {
        let mut settings = DevicePluginSettings::default();
        assert_eq!(time_slicing_config(&settings), None);
        settings.device_sharing_strategy = DeviceSharingStrategy::TimeSlicing;
        let config = time_slicing_config(&settings).unwrap();
        assert!(config.contains("replicas: 2\n"), "{config}");
        let (_, workload) = device_plugin(&settings, "595.112.07").unwrap();
        assert_eq!(workload.mounts[2].destination.as_str(), "/config");
    }

    #[test]
    fn the_versions_are_the_recipes() {
        for (recipe, version) in [
            ("nvidia-k8s-device-plugin.toml", DEVICE_PLUGIN_VERSION),
            ("nvidia-dra-kubelet-plugin.toml", DRA_VERSION),
        ] {
            let path = format!(
                "{}/../../specs/targets/kubernetes-1-37-nvidia/components/{recipe}",
                env!("CARGO_MANIFEST_DIR")
            );
            let text = std::fs::read_to_string(&path).unwrap();
            assert!(
                text.starts_with(&format!("version = \"{version}\"\n")),
                "{path}"
            );
        }
    }
}

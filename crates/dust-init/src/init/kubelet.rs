//! kubelet, run by dust-init when the image ships it and user-data enables
//! `settings.kubernetes`.
//!
//! dust-init writes kubelet's configuration and credentials to `/run/kubelet` at every boot, from
//! user-data alone; kubelet keeps its state (its rotated client certificate included) in
//! `/var/lib/kubelet`. It talks to containerd's CRI plugin with the cgroupfs driver: there is no
//! systemd.

use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::Path;

use anyhow::Context;
use rustix::mount::MountPropagationFlags;
use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

use crate::init::containerd;
use crate::init::service::{Service, Spec};
use crate::process::Reaper;
use crate::settings::{CloudProvider, EvictionSignal, KubeletConfig, Quantity, ReservedResource};
use crate::types::Hostname;

const PROGRAM: &str = "/usr/bin/kubelet";
const LOG: &str = "/var/log/kubelet.log";
/// Rewritten at every boot from user-data: configuration and credentials.
const RUN_DIR: &str = "/run/kubelet";
const CONFIG: &str = "/run/kubelet/config.json";
const KUBECONFIG: &str = "/run/kubelet/kubeconfig";
const BOOTSTRAP_KUBECONFIG: &str = "/run/kubelet/bootstrap-kubeconfig";
const CLUSTER_CA: &str = "/run/kubelet/ca.crt";
/// The client certificate kubelet obtains by TLS bootstrapping, then rotates (`--cert-dir`).
const ROTATED_CERTIFICATE: &str = "/var/lib/kubelet/pki/kubelet-client-current.pem";
/// `staticPodPath`: the manifests of `settings.kubernetes.static-pods`, rewritten at every boot,
/// so a pod removed from user-data is gone after the next one.
const MANIFESTS: &str = "/run/kubelet/manifests";
/// FlexVolume drivers; kubelet's default is under `/usr`, read-only.
const VOLUME_PLUGIN_DIR: &str = "/var/lib/kubelet/volumeplugins";
/// Writable directories the image's `/opt/cni/bin` and `/etc/cni/net.d` link to, where network
/// add-ons install their plugins and configuration.
const WRITABLE_DIRS: &[&str] = &["/var/lib/kubelet", "/var/lib/cni/bin", "/run/cni/net.d"];

/// Whether the image ships kubelet.
pub fn installed() -> bool {
    Path::new(PROGRAM).exists()
}

/// What kubelet runs with: its files (path, contents, whether secret) and arguments.
#[derive(Debug)]
struct Rendered {
    files: Vec<(String, String, bool)>,
    args: Vec<String>,
}

/// Prepares the host for kubelet: its files, the writable directories, and shared mount
/// propagation. Returns kubelet's arguments. Runs before containerd starts, so the mounts
/// containerd makes are shared too.
pub fn prepare(config: &KubeletConfig, node_name: &Hostname) -> anyhow::Result<Vec<String>> {
    // Volumes with `Bidirectional` or `HostToContainer` propagation (CSI drivers, Cilium's bpffs)
    // need shared host mounts; kubelet itself only shares /var/lib/kubelet.
    rustix::mount::mount_change(c"/", MountPropagationFlags::SHARED | MountPropagationFlags::REC)
        .context("making the mounts shared")?;
    for dir in WRITABLE_DIRS {
        std::fs::create_dir_all(dir).with_context(|| format!("creating {dir}"))?;
    }
    for dir in [RUN_DIR, MANIFESTS] {
        match std::fs::DirBuilder::new().mode(0o700).create(dir) {
            Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e).context(dir)?,
            _ => {}
        }
    }
    let rendered = render(config, node_name);
    for (path, contents, secret) in &rendered.files {
        write(Path::new(path), contents, *secret).with_context(|| format!("writing {path}"))?;
    }
    Ok(rendered.args)
}

pub fn start(reaper: Reaper, args: Vec<String>) -> Service {
    let spec = Spec {
        name: "kubelet",
        program: PROGRAM,
        args,
        log: LOG,
    };
    Service::start(reaper, spec)
}

fn write(path: &Path, contents: &str, secret: bool) -> std::io::Result<()> {
    use std::io::Write as _;
    let mode = if secret { 0o600 } else { 0o644 };
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(path)?;
    file.write_all(contents.as_bytes())
}

fn render(config: &KubeletConfig, node_name: &Hostname) -> Rendered {
    let server = config.api_server.as_str();
    // Until it has a valid certificate there, kubelet requests one with the bootstrap kubeconfig,
    // then writes its own kubeconfig, in place of this one.
    let rotated = json!({"client-certificate": ROTATED_CERTIFICATE, "client-key": ROTATED_CERTIFICATE});
    let token = json!({"token": config.bootstrap_token.expose()});
    let mut files = vec![
        (
            CLUSTER_CA.to_owned(),
            config.cluster_certificate.pem().to_owned(),
            false,
        ),
        (CONFIG.to_owned(), kubelet_configuration(config), false),
        (KUBECONFIG.to_owned(), kubeconfig(server, rotated), true),
        (BOOTSTRAP_KUBECONFIG.to_owned(), kubeconfig(server, token), true),
    ];
    let mut args = vec![
        format!("--config={CONFIG}"),
        format!("--kubeconfig={KUBECONFIG}"),
        format!("--bootstrap-kubeconfig={BOOTSTRAP_KUBECONFIG}"),
        format!("--hostname-override={node_name}"),
    ];
    // Manifests may hold credentials, as pods' environments often do.
    for (name, pod) in config.static_pods.iter().filter(|(_, pod)| pod.enabled) {
        files.push((format!("{MANIFESTS}/{name}.yaml"), pod.manifest.text().to_owned(), true));
    }
    if !config.node_labels.is_empty() {
        let labels: Vec<String> = config.node_labels.iter().map(|(k, v)| format!("{k}={v}")).collect();
        args.push(format!("--node-labels={}", labels.join(",")));
    }
    if let Some(CloudProvider::External) = config.cloud_provider {
        args.push("--cloud-provider=external".into());
    }
    Rendered { files, args }
}

/// kubelet's `KubeletConfiguration`, in JSON (which it reads as YAML).
fn kubelet_configuration(config: &KubeletConfig) -> String {
    let taints: Vec<Value> = config
        .node_taints
        .iter()
        .flat_map(|(key, taints)| {
            taints.iter().map(move |taint| {
                json!({"key": key.as_str(), "value": taint.value.as_str(), "effect": taint.effect.as_str()})
            })
        })
        .collect();
    let reserved = |resources: &BTreeMap<ReservedResource, Quantity>| -> Map<String, Value> {
        resources
            .iter()
            .map(|(resource, quantity)| (resource.as_str().to_owned(), quantity.as_str().into()))
            .collect()
    };
    let eviction_hard = by_signal(&config.eviction_hard);
    let eviction_soft = by_signal(&config.eviction_soft);
    let grace_periods = by_signal(&config.eviction_soft_grace_period);
    let mut configuration = json!({
        "apiVersion": "kubelet.config.k8s.io/v1beta1",
        "kind": "KubeletConfiguration",
        "cgroupDriver": "cgroupfs",
        "containerRuntimeEndpoint": format!("unix://{}", containerd::SOCKET),
        "authentication": {
            "anonymous": {"enabled": false},
            "webhook": {"enabled": true},
            "x509": {"clientCAFile": CLUSTER_CA},
        },
        "authorization": {"mode": "Webhook"},
        "readOnlyPort": 0,
        "rotateCertificates": true,
        "clusterDomain": config.cluster_domain.as_str(),
        "clusterDNS": config.cluster_dns_ip.as_slice(),
        "registerWithTaints": taints,
        "resolvConf": "/etc/resolv.conf",
        "staticPodPath": MANIFESTS,
        "volumePluginDir": VOLUME_PLUGIN_DIR,
    });
    // Left out, kubelet's defaults apply.
    let optional = [
        ("maxPods", config.max_pods.map(|n| n.get().into())),
        (
            "kubeReserved",
            (!config.kube_reserved.is_empty()).then(|| reserved(&config.kube_reserved).into()),
        ),
        (
            "systemReserved",
            (!config.system_reserved.is_empty()).then(|| reserved(&config.system_reserved).into()),
        ),
        (
            "evictionHard",
            (!eviction_hard.is_empty()).then(|| eviction_hard.into()),
        ),
        (
            "evictionSoft",
            (!eviction_soft.is_empty()).then(|| eviction_soft.into()),
        ),
        (
            "evictionSoftGracePeriod",
            (!grace_periods.is_empty()).then(|| grace_periods.into()),
        ),
        (
            "evictionMaxPodGracePeriod",
            config.eviction_max_pod_grace_period.map(Value::from),
        ),
        (
            "imageGCHighThresholdPercent",
            config.image_gc.high_threshold_percent.map(|p| p.get().into()),
        ),
        (
            "imageGCLowThresholdPercent",
            config.image_gc.low_threshold_percent.map(|p| p.get().into()),
        ),
        (
            "imageMinimumGCAge",
            config.image_gc.minimum_age.as_ref().map(|d| d.as_str().into()),
        ),
        (
            "imageMaximumGCAge",
            config.image_gc.maximum_age.as_ref().map(|d| d.as_str().into()),
        ),
    ];
    for (key, value) in optional {
        if let Some(value) = value {
            configuration[key] = value;
        }
    }
    pretty(&configuration)
}

/// Eviction settings by signal name, as kubelet's configuration takes them.
fn by_signal<V: AsRef<str>>(values: &BTreeMap<EvictionSignal, V>) -> Map<String, Value> {
    values
        .iter()
        .map(|(signal, value)| (signal.as_str().to_owned(), value.as_ref().into()))
        .collect()
}

/// A kubeconfig with one cluster, the API server trusted through the cluster CA, and `user`.
fn kubeconfig(server: &str, user: Value) -> String {
    pretty(&json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{"name": "kubernetes", "cluster": {"server": server, "certificate-authority": CLUSTER_CA}}],
        "users": [{"name": "kubelet", "user": user}],
        "contexts": [{"name": "kubelet", "context": {"cluster": "kubernetes", "user": "kubelet"}}],
        "current-context": "kubelet",
    }))
}

fn pretty(value: &Value) -> String {
    // Serializing a `Value` cannot fail.
    serde_json::to_string_pretty(value).unwrap_or_default() + "\n"
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::settings::{KubernetesSettings, UserData};

    fn base64(text: &str) -> String {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(text)
    }

    fn config(extra: &str) -> Box<KubeletConfig> {
        let key = rcgen::KeyPair::generate().unwrap();
        let ca = rcgen::CertificateParams::new(vec!["ca".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let document = format!(
            "[settings.kubernetes]\nenabled = true\napi-server = \"https://k8s.example.com:6443\"\n\
             cluster-certificate = \"{}\"\nbootstrap-token = \"abcdef.0123456789abcdef\"\n{extra}\n",
            base64(&ca.pem())
        );
        match UserData::parse(document.as_bytes()).unwrap().settings.kubernetes {
            KubernetesSettings::Enabled(config) => config,
            KubernetesSettings::Disabled => panic!("kubernetes should be enabled"),
        }
    }

    fn file<'a>(rendered: &'a Rendered, path: &str) -> (&'a str, bool) {
        let (_, contents, secret) = rendered.files.iter().find(|(p, ..)| *p == path).unwrap();
        (contents, *secret)
    }

    fn json(text: &str) -> Value {
        serde_json::from_str(text).unwrap()
    }

    #[test]
    fn defaults() {
        let rendered = render(&config(""), &"node-1.example.com".parse().unwrap());
        assert_eq!(
            rendered.args,
            [
                "--config=/run/kubelet/config.json",
                "--kubeconfig=/run/kubelet/kubeconfig",
                "--bootstrap-kubeconfig=/run/kubelet/bootstrap-kubeconfig",
                "--hostname-override=node-1.example.com",
            ]
        );
        let (bootstrap, secret) = file(&rendered, BOOTSTRAP_KUBECONFIG);
        assert!(secret);
        let bootstrap = json(bootstrap);
        assert_eq!(bootstrap["users"][0]["user"]["token"], "abcdef.0123456789abcdef");
        assert_eq!(
            bootstrap["clusters"][0]["cluster"]["server"],
            "https://k8s.example.com:6443"
        );
        assert_eq!(bootstrap["clusters"][0]["cluster"]["certificate-authority"], CLUSTER_CA);
        let (kubeconfig, secret) = file(&rendered, KUBECONFIG);
        assert!(secret);
        let kubeconfig = json(kubeconfig);
        assert_eq!(
            kubeconfig["users"][0]["user"]["client-certificate"],
            ROTATED_CERTIFICATE
        );
        assert_eq!(kubeconfig["current-context"], "kubelet");

        let configuration = json(file(&rendered, CONFIG).0);
        assert_eq!(configuration["kind"], "KubeletConfiguration");
        assert_eq!(configuration["cgroupDriver"], "cgroupfs");
        assert_eq!(
            configuration["containerRuntimeEndpoint"],
            "unix:///run/containerd/containerd.sock"
        );
        assert_eq!(configuration["authentication"]["anonymous"]["enabled"], false);
        assert_eq!(configuration["authentication"]["x509"]["clientCAFile"], CLUSTER_CA);
        assert_eq!(configuration["authorization"]["mode"], "Webhook");
        assert_eq!(configuration["rotateCertificates"], true);
        assert_eq!(configuration["clusterDomain"], "cluster.local");
        assert_eq!(configuration["staticPodPath"], MANIFESTS);
        for key in [
            "maxPods",
            "kubeReserved",
            "systemReserved",
            "evictionHard",
            "evictionSoft",
            "evictionSoftGracePeriod",
            "evictionMaxPodGracePeriod",
            "imageGCHighThresholdPercent",
            "imageGCLowThresholdPercent",
            "imageMinimumGCAge",
            "imageMaximumGCAge",
        ] {
            assert!(configuration.get(key).is_none(), "{key} set");
        }
        assert!(file(&rendered, CLUSTER_CA).0.starts_with("-----BEGIN CERTIFICATE-----"));
    }

    #[test]
    fn options() {
        let pod = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n";
        let extra = format!(
            r#"
cluster-domain = "corp.internal"
cluster-dns-ip = "10.96.0.10"
max-pods = 50
eviction-max-pod-grace-period = 60
cloud-provider = "external"
image-gc-high-threshold-percent = 90
image-gc-low-threshold-percent = "70"
image-minimum-gc-age = "5m"
image-maximum-gc-age = "168h"

[settings.kubernetes.node-labels]
"node.kubernetes.io/pool" = "blue"
tier = "web"

[settings.kubernetes.node-taints]
dedicated = ["gpu:NoSchedule", ":NoExecute"]

[settings.kubernetes.kube-reserved]
cpu = "100m"
memory = "512Mi"

[settings.kubernetes.system-reserved]
ephemeral-storage = "1Gi"
pid = "1000"

[settings.kubernetes.eviction-hard]
"memory.available" = "15%"
"nodefs.inodesFree" = "5%"

[settings.kubernetes.eviction-soft]
"memory.available" = "20%"

[settings.kubernetes.eviction-soft-grace-period]
"memory.available" = "1m30s"

[settings.kubernetes.static-pods.web]
manifest = "{pod}"

[settings.kubernetes.static-pods.off]
enabled = false
manifest = "{pod}"
"#,
            pod = base64(pod)
        );
        let rendered = render(&config(&extra), &"node-1".parse().unwrap());
        assert_eq!(
            rendered.args[4..],
            [
                "--node-labels=node.kubernetes.io/pool=blue,tier=web",
                "--cloud-provider=external"
            ]
        );
        assert!(!rendered.args.iter().any(|arg| arg.starts_with("--node-ip")));

        let configuration = json(file(&rendered, CONFIG).0);
        assert_eq!(configuration["clusterDomain"], "corp.internal");
        assert_eq!(configuration["clusterDNS"], json(r#"["10.96.0.10"]"#));
        assert_eq!(configuration["maxPods"], 50);
        assert_eq!(
            configuration["kubeReserved"],
            json(r#"{"cpu": "100m", "memory": "512Mi"}"#)
        );
        assert_eq!(
            configuration["systemReserved"],
            json(r#"{"ephemeral-storage": "1Gi", "pid": "1000"}"#)
        );
        assert_eq!(
            configuration["evictionHard"],
            json(r#"{"memory.available": "15%", "nodefs.inodesFree": "5%"}"#)
        );
        assert_eq!(configuration["evictionSoft"], json(r#"{"memory.available": "20%"}"#));
        assert_eq!(
            configuration["evictionSoftGracePeriod"],
            json(r#"{"memory.available": "1m30s"}"#)
        );
        assert_eq!(configuration["evictionMaxPodGracePeriod"], 60);
        assert_eq!(configuration["imageGCHighThresholdPercent"], 90);
        assert_eq!(configuration["imageGCLowThresholdPercent"], 70);
        assert_eq!(configuration["imageMinimumGCAge"], "5m");
        assert_eq!(configuration["imageMaximumGCAge"], "168h");
        assert_eq!(file(&rendered, "/run/kubelet/manifests/web.yaml"), (pod, true));
        assert!(
            !rendered.files.iter().any(|(path, ..)| path.ends_with("off.yaml")),
            "disabled"
        );
        assert_eq!(
            configuration["registerWithTaints"],
            json(
                r#"[{"key": "dedicated", "value": "gpu", "effect": "NoSchedule"},
                    {"key": "dedicated", "value": "", "effect": "NoExecute"}]"#
            )
        );
    }
}

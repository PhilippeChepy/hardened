//! kubelet's files and arguments, rendered from its configuration.
//!
//! Its configuration and credentials go to `/run/kubelet`, written again at every boot; its state
//! (its rotated client certificate included) stays in `/var/lib/kubelet`, with the static pods'
//! manifests. It talks to containerd's CRI plugin with the cgroupfs driver: there is no systemd.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::fs::Permissions;
use std::io;
use std::io::ErrorKind;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use controllers_helpers::Hostname;
use controllers_helpers::atomic_file;
use kubelet_controller::CloudProvider;
use kubelet_controller::ImageAges;
use kubelet_controller::KubeletConfig;
use kubelet_controller::ThresholdPercents;
use serde::Deserialize;
use serde::Serialize;
use serde_json::Map;
use serde_json::Value;
use serde_json::json;

pub const PROGRAM: &str = "/usr/bin/kubelet";
/// Configuration and credentials, readable by root only.
const RUN_DIR: &str = "/run/kubelet";
const CONFIG: &str = "/run/kubelet/config.json";
const KUBECONFIG: &str = "/run/kubelet/kubeconfig";
const BOOTSTRAP_KUBECONFIG: &str = "/run/kubelet/bootstrap-kubeconfig";
const CLUSTER_CA: &str = "/run/kubelet/ca.crt";
/// The client certificate kubelet obtains by TLS bootstrapping, then rotates (`--cert-dir`).
const ROTATED_CERTIFICATE: &str = "/var/lib/kubelet/pki/kubelet-client-current.pem";
/// `staticPodPath`: the manifests of `settings.kubernetes.static-pods`, and nothing else (the
/// others are removed).
const MANIFESTS: &str = "/var/lib/kubelet/manifests";
/// FlexVolume drivers; kubelet's default is under `/usr`, read-only.
const VOLUME_PLUGIN_DIR: &str = "/var/lib/kubelet/volumeplugins";
const CONTAINERD_SOCKET: &str = "/run/containerd/containerd.sock";

/// What kubelet runs with: its files and arguments.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rendered {
    files: Vec<RenderedFile>,
    args: Vec<String>,
}

/// A file kubelet reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct RenderedFile {
    path: String,
    contents: String,
    /// Readable by root only (credentials).
    secret: bool,
}

impl RenderedFile {
    #[must_use]
    fn public(path: &str, contents: String) -> Self {
        Self {
            path: path.to_owned(),
            contents,
            secret: false,
        }
    }

    #[must_use]
    fn secret(path: &str, contents: String) -> Self {
        Self {
            path: path.to_owned(),
            contents,
            secret: true,
        }
    }
}

impl Rendered {
    /// kubelet's arguments, after its program.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Writes the files below `root` (`/` but in tests), and removes the manifests of static
    /// pods no longer declared.
    ///
    /// # Errors
    ///
    /// When a directory or file cannot be written.
    pub fn write(&self, root: &Path) -> io::Result<()> {
        let at = |path: &str| root.join(path.trim_start_matches('/'));
        for dir in [RUN_DIR, MANIFESTS] {
            fs::create_dir_all(at(dir))?;
            fs::set_permissions(at(dir), Permissions::from_mode(0o700))?;
        }
        let mut written = BTreeSet::new();
        for file in &self.files {
            let mode = if file.secret { 0o600 } else { 0o644 };
            let path = at(&file.path);
            atomic_file::write(&path, file.contents.as_bytes(), mode)?;
            written.insert(path);
        }
        for entry in fs::read_dir(at(MANIFESTS))? {
            let path = entry?.path();
            if !written.contains(&path) {
                remove_file(&path)?;
            }
        }
        Ok(())
    }
}

fn remove_file(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(error) if error.kind() != ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}

/// What kubelet runs with to join the cluster `config` describes, as the node `node_name`.
#[must_use]
pub fn render(config: &KubeletConfig, node_name: &Hostname) -> Rendered {
    let server = config.api_server.as_str();
    // Until it has a valid certificate there, kubelet requests one with the bootstrap kubeconfig,
    // then writes its own kubeconfig, in place of this one.
    let rotated =
        json!({"client-certificate": ROTATED_CERTIFICATE, "client-key": ROTATED_CERTIFICATE});
    let token = json!({"token": config.bootstrap_token.expose()});
    let mut files = vec![
        RenderedFile::public(CLUSTER_CA, config.cluster_certificate.pem().to_owned()),
        RenderedFile::public(CONFIG, kubelet_configuration(config)),
        RenderedFile::secret(KUBECONFIG, kubeconfig(server, rotated)),
        RenderedFile::secret(BOOTSTRAP_KUBECONFIG, kubeconfig(server, token)),
    ];
    let mut args = vec![
        format!("--config={CONFIG}"),
        format!("--kubeconfig={KUBECONFIG}"),
        format!("--bootstrap-kubeconfig={BOOTSTRAP_KUBECONFIG}"),
        format!("--hostname-override={node_name}"),
    ];
    for (name, pod) in &config.static_pods {
        if pod.enabled {
            // Secret: pods' environments often hold credentials.
            let path = format!("{MANIFESTS}/{name}.yaml");
            files.push(RenderedFile::secret(&path, pod.manifest.text().to_owned()));
        }
    }
    if !config.node_labels.is_empty() {
        let labels: Vec<String> = config
            .node_labels
            .iter()
            .map(|(key, value)| format!("{key}={value}"))
            .collect();
        args.push(format!("--node-labels={}", labels.join(",")));
    }
    if let Some(CloudProvider::External) = config.cloud_provider {
        args.push("--cloud-provider=external".into());
    }
    Rendered { files, args }
}

/// kubelet's `KubeletConfiguration`, in JSON (which it reads as YAML).
#[must_use]
fn kubelet_configuration(config: &KubeletConfig) -> String {
    let mut taints = Vec::new();
    for (key, values) in &config.node_taints {
        for taint in values {
            taints.push(json!({
                "key": key.as_str(),
                "value": taint.value.as_str(),
                "effect": taint.effect.as_str(),
            }));
        }
    }
    let mut configuration = json!({
        "apiVersion": "kubelet.config.k8s.io/v1beta1",
        "kind": "KubeletConfiguration",
        "cgroupDriver": "cgroupfs",
        "containerRuntimeEndpoint": format!("unix://{CONTAINERD_SOCKET}"),
        "authentication": {
            "anonymous": {"enabled": false},
            "webhook": {"enabled": true},
            "x509": {"clientCAFile": CLUSTER_CA},
        },
        "authorization": {"mode": "Webhook"},
        "readOnlyPort": 0,
        "rotateCertificates": true,
        "clusterDomain": config.cluster_domain.as_str(),
        "clusterDNS": config.cluster_dns_ip,
        "registerWithTaints": taints,
        "resolvConf": "/etc/resolv.conf",
        "staticPodPath": MANIFESTS,
        "volumePluginDir": VOLUME_PLUGIN_DIR,
    });
    let (soft, soft_grace_period): (BTreeMap<_, _>, BTreeMap<_, _>) = config
        .eviction_soft
        .iter()
        .map(|(signal, soft)| ((signal, &soft.threshold), (signal, soft.grace_period)))
        .unzip();
    let thresholds = config.image_gc.threshold_percent;
    let ages = config.image_gc.age;
    let optional = [
        ("maxPods", json!(config.max_pods)),
        ("kubeReserved", json!(config.kube_reserved)),
        ("systemReserved", json!(config.system_reserved)),
        ("evictionHard", json!(config.eviction_hard)),
        ("evictionSoft", json!(soft)),
        ("evictionSoftGracePeriod", json!(soft_grace_period)),
        (
            "evictionMaxPodGracePeriod",
            json!(config.eviction_max_pod_grace_period),
        ),
        (
            "imageGCHighThresholdPercent",
            json!(thresholds.map(ThresholdPercents::high)),
        ),
        (
            "imageGCLowThresholdPercent",
            json!(thresholds.map(ThresholdPercents::low)),
        ),
        ("imageMinimumGCAge", json!(ages.map(ImageAges::minimum))),
        (
            "imageMaximumGCAge",
            json!(ages.and_then(ImageAges::maximum)),
        ),
    ];
    // Left out (absent or empty), kubelet's defaults apply.
    for (key, value) in optional {
        let empty = value.is_null() || value.as_object().is_some_and(Map::is_empty);
        if !empty {
            configuration[key] = value;
        }
    }
    pretty(&configuration)
}

/// A kubeconfig with one cluster, the API server trusted through the cluster CA, and `user`.
#[must_use]
fn kubeconfig(server: &str, user: Value) -> String {
    pretty(&json!({
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": "kubernetes",
            "cluster": {"server": server, "certificate-authority": CLUSTER_CA},
        }],
        "users": [{"name": "kubelet", "user": user}],
        "contexts": [{
            "name": "kubelet",
            "context": {"cluster": "kubernetes", "user": "kubelet"},
        }],
        "current-context": "kubelet",
    }))
}

/// `value` as pretty JSON, ending with a newline.
#[must_use]
fn pretty(value: &Value) -> String {
    // A `Value`'s alternate `Display` is its pretty JSON, which cannot fail.
    format!("{value:#}\n")
}

#[cfg(test)]
pub(crate) mod tests {
    use controllers_helpers::base64_text;
    use controllers_helpers::testing;

    use super::*;

    /// `settings.kubernetes`, with `extra` keys.
    pub(crate) fn config(extra: &str) -> KubeletConfig {
        let (ca, _) = testing::certificate_and_key();
        let document = format!(
            "api-server = \"https://k8s.example.com:6443\"\n\
             cluster-certificate = \"{}\"\n\
             bootstrap-token = \"abcdef.0123456789abcdef\"\n{extra}\n",
            base64_text::encode(ca)
        );
        toml::from_str(&document).unwrap()
    }

    const POD: &str = "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\n";

    /// Static pods `web` (enabled) and `off` (disabled).
    pub(crate) fn static_pods() -> String {
        format!(
            "[static-pods.web]\nmanifest = \"{pod}\"\n\n\
             [static-pods.off]\nenabled = false\nmanifest = \"{pod}\"\n",
            pod = base64_text::encode(POD)
        )
    }

    fn file<'a>(rendered: &'a Rendered, path: &str) -> (&'a str, bool) {
        let file = rendered
            .files
            .iter()
            .find(|file| file.path == path)
            .unwrap_or_else(|| panic!("{path} not rendered"));
        (&file.contents, file.secret)
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
        assert_eq!(
            bootstrap["users"][0]["user"]["token"],
            "abcdef.0123456789abcdef"
        );
        assert_eq!(
            bootstrap["clusters"][0]["cluster"]["server"],
            "https://k8s.example.com:6443"
        );
        assert_eq!(
            bootstrap["clusters"][0]["cluster"]["certificate-authority"],
            CLUSTER_CA
        );
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
        assert_eq!(
            configuration["authentication"]["anonymous"]["enabled"],
            false
        );
        assert_eq!(
            configuration["authentication"]["x509"]["clientCAFile"],
            CLUSTER_CA
        );
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
        assert!(
            file(&rendered, CLUSTER_CA)
                .0
                .starts_with("-----BEGIN CERTIFICATE-----")
        );
    }

    #[test]
    fn options() {
        let extra = format!(
            r#"
cluster-domain = "corp.internal"
cluster-dns-ip = ["10.96.0.10"]
max-pods = 50
eviction-max-pod-grace-period = 60
cloud-provider = "external"
image-gc-high-threshold-percent = 90
image-gc-low-threshold-percent = 70
image-minimum-gc-age = "5m"
image-maximum-gc-age = "168h"

[node-labels]
"node.kubernetes.io/pool" = "blue"
tier = "web"

[node-taints]
dedicated = ["gpu:NoSchedule", ":NoExecute"]

[kube-reserved]
cpu = "100m"
memory = "512Mi"

[system-reserved]
ephemeral-storage = "1Gi"
pid = "1000"

[eviction-hard]
"memory.available" = "15%"
"nodefs.inodesFree" = "5%"

[eviction-soft]
"memory.available" = "20%"

[eviction-soft-grace-period]
"memory.available" = "1m30s"

{}"#,
            static_pods()
        );
        let rendered = render(&config(&extra), &"node-1".parse().unwrap());
        assert_eq!(
            rendered.args[4..],
            [
                "--node-labels=node.kubernetes.io/pool=blue,tier=web",
                "--cloud-provider=external"
            ]
        );

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
        assert_eq!(
            configuration["evictionSoft"],
            json(r#"{"memory.available": "20%"}"#)
        );
        assert_eq!(
            configuration["evictionSoftGracePeriod"],
            json(r#"{"memory.available": "1m30s"}"#)
        );
        assert_eq!(configuration["evictionMaxPodGracePeriod"], 60);
        assert_eq!(configuration["imageGCHighThresholdPercent"], 90);
        assert_eq!(configuration["imageGCLowThresholdPercent"], 70);
        assert_eq!(configuration["imageMinimumGCAge"], "5m");
        assert_eq!(configuration["imageMaximumGCAge"], "168h");
        assert_eq!(
            file(&rendered, "/var/lib/kubelet/manifests/web.yaml"),
            (POD, true)
        );
        assert!(
            !rendered
                .files
                .iter()
                .any(|file| file.path.ends_with("off.yaml")),
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

    #[test]
    fn writes_the_files_and_removes_stale_manifests() {
        use std::os::unix::fs::MetadataExt;

        let root = tempfile::tempdir().unwrap();
        let manifests = root.path().join("var/lib/kubelet/manifests");
        fs::create_dir_all(&manifests).unwrap();
        fs::write(manifests.join("old.yaml"), POD).unwrap();

        let rendered = render(&config(&static_pods()), &"node-1".parse().unwrap());
        rendered.write(root.path()).unwrap();
        rendered.write(root.path()).unwrap();
        let names: Vec<_> = fs::read_dir(&manifests)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["web.yaml"]);
        let mode = |path: &str| fs::metadata(root.path().join(path)).unwrap().mode() & 0o777;
        assert_eq!(mode("run/kubelet"), 0o700);
        assert_eq!(mode("run/kubelet/bootstrap-kubeconfig"), 0o600);
        assert_eq!(mode("run/kubelet/config.json"), 0o644);
        assert_eq!(mode("var/lib/kubelet/manifests/web.yaml"), 0o600);
    }
}

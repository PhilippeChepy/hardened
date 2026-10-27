//! `[settings.kubernetes]`: the kubelet of images that ship it, with Bottlerocket's keys and
//! value formats (`bottlerocket-settings-models`, `settings-extensions/kubernetes`).
//!
//! Everything kubelet would reject at startup (a node label in a namespace it may not set, a
//! malformed taint, a low image GC threshold above the high one) is rejected here instead, so a
//! typo shows in the user-data error rather than in a crash-looping kubelet.

mod resources;

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::num::NonZeroU16;

use serde::{Deserialize, Serialize};

pub use resources::{Duration, EvictionSignal, ImageGc, Percent, Quantity, ReservedResource, Threshold};

use crate::types::{Certificates, DomainName, InvalidValue, PrivateKey, WorkloadName, validated_string};

/// Whether dust-init runs kubelet. Enabling it requires the API server, its CA and a bootstrap
/// token, so an enabled kubelet that cannot join a cluster cannot be represented.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawKubernetesSettings", into = "RawKubernetesSettings")]
pub enum KubernetesSettings {
    #[default]
    Disabled,
    Enabled(Box<KubeletConfig>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KubeletConfig {
    pub api_server: ApiServerUrl,
    /// The cluster CA: the API server's certificate chains to it, and so do the client
    /// certificates kubelet's own API accepts.
    pub cluster_certificate: Certificates,
    /// TLS bootstrapping: kubelet requests its client certificate with it, then rotates it.
    pub bootstrap_token: BootstrapToken,
    pub cluster_domain: DomainName,
    pub cluster_dns_ip: IpAddrs,
    pub node_labels: BTreeMap<QualifiedName, LabelValue>,
    pub node_taints: BTreeMap<QualifiedName, Vec<TaintValue>>,
    pub max_pods: Option<NonZeroU16>,
    pub cloud_provider: Option<CloudProvider>,
    /// Pods kubelet runs from files, without the API server; by file name.
    pub static_pods: BTreeMap<WorkloadName, StaticPod>,
    pub kube_reserved: BTreeMap<ReservedResource, Quantity>,
    pub system_reserved: BTreeMap<ReservedResource, Quantity>,
    /// Replaces kubelet's defaults as a whole: a signal left out is not checked.
    pub eviction_hard: BTreeMap<EvictionSignal, Threshold>,
    pub image_gc: ImageGc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudProvider {
    /// A cloud controller manager initializes the node (kubelet's `--cloud-provider=external`).
    External,
}

/// IP addresses, written as one address or a list (Bottlerocket's `cluster-dns-ip` takes both).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "OneOrMany", into = "OneOrMany")]
pub struct IpAddrs(Vec<IpAddr>);

impl IpAddrs {
    pub fn as_slice(&self) -> &[IpAddr] {
        &self.0
    }

    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(IpAddr),
    Many(Vec<IpAddr>),
}

impl From<OneOrMany> for IpAddrs {
    fn from(value: OneOrMany) -> Self {
        match value {
            OneOrMany::One(ip) => Self(vec![ip]),
            OneOrMany::Many(ips) => Self(ips),
        }
    }
}

impl From<IpAddrs> for OneOrMany {
    fn from(ips: IpAddrs) -> Self {
        match ips.0.as_slice() {
            [ip] => Self::One(*ip),
            _ => Self::Many(ips.0),
        }
    }
}

/// `[settings.kubernetes]` as written in user-data.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawKubernetesSettings {
    #[serde(default)]
    enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    api_server: Option<ApiServerUrl>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cluster_certificate: Option<Certificates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bootstrap_token: Option<BootstrapToken>,
    #[serde(default = "default_cluster_domain")]
    cluster_domain: DomainName,
    #[serde(default, skip_serializing_if = "IpAddrs::is_empty")]
    cluster_dns_ip: IpAddrs,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    node_labels: BTreeMap<QualifiedName, LabelValue>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    node_taints: BTreeMap<QualifiedName, Vec<TaintValue>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_pods: Option<NonZeroU16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cloud_provider: Option<CloudProvider>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    static_pods: BTreeMap<WorkloadName, StaticPod>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    kube_reserved: BTreeMap<ReservedResource, Quantity>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    system_reserved: BTreeMap<ReservedResource, Quantity>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    eviction_hard: BTreeMap<EvictionSignal, Threshold>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_gc_high_threshold_percent: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_gc_low_threshold_percent: Option<Percent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_minimum_gc_age: Option<Duration>,
    #[serde(skip_serializing_if = "Option::is_none")]
    image_maximum_gc_age: Option<Duration>,
}

fn default_cluster_domain() -> DomainName {
    DomainName::try_from("cluster.local".to_owned()).expect("a valid domain name")
}

impl TryFrom<RawKubernetesSettings> for KubernetesSettings {
    type Error = String;

    fn try_from(raw: RawKubernetesSettings) -> Result<Self, Self::Error> {
        if !raw.enabled {
            return Ok(Self::Disabled);
        }
        let (Some(api_server), Some(cluster_certificate), Some(bootstrap_token)) =
            (raw.api_server, raw.cluster_certificate, raw.bootstrap_token)
        else {
            return Err(
                "api-server, cluster-certificate and bootstrap-token are required when kubernetes is enabled".into(),
            );
        };
        if let Some(key) = raw.node_labels.keys().find(|key| !kubelet_may_set(key)) {
            return Err(format!(
                "node label {key}: kubelet may only set the kubernetes.io and k8s.io labels of the \
                 kubelet.kubernetes.io and node.kubernetes.io namespaces, and a few well-known ones"
            ));
        }
        let image_gc = ImageGc {
            high_threshold_percent: raw.image_gc_high_threshold_percent,
            low_threshold_percent: raw.image_gc_low_threshold_percent,
            minimum_age: raw.image_minimum_gc_age,
            maximum_age: raw.image_maximum_gc_age,
        };
        image_gc.check()?;
        Ok(Self::Enabled(Box::new(KubeletConfig {
            api_server,
            cluster_certificate,
            bootstrap_token,
            cluster_domain: raw.cluster_domain,
            cluster_dns_ip: raw.cluster_dns_ip,
            node_labels: raw.node_labels,
            node_taints: raw.node_taints,
            max_pods: raw.max_pods,
            cloud_provider: raw.cloud_provider,
            static_pods: raw.static_pods,
            kube_reserved: raw.kube_reserved,
            system_reserved: raw.system_reserved,
            eviction_hard: raw.eviction_hard,
            image_gc,
        })))
    }
}

impl From<KubernetesSettings> for RawKubernetesSettings {
    fn from(settings: KubernetesSettings) -> Self {
        let KubernetesSettings::Enabled(config) = settings else {
            return Self {
                enabled: false,
                api_server: None,
                cluster_certificate: None,
                bootstrap_token: None,
                cluster_domain: default_cluster_domain(),
                cluster_dns_ip: IpAddrs::default(),
                node_labels: BTreeMap::new(),
                node_taints: BTreeMap::new(),
                max_pods: None,
                cloud_provider: None,
                static_pods: BTreeMap::new(),
                kube_reserved: BTreeMap::new(),
                system_reserved: BTreeMap::new(),
                eviction_hard: BTreeMap::new(),
                image_gc_high_threshold_percent: None,
                image_gc_low_threshold_percent: None,
                image_minimum_gc_age: None,
                image_maximum_gc_age: None,
            };
        };
        let config = *config;
        Self {
            enabled: true,
            api_server: Some(config.api_server),
            cluster_certificate: Some(config.cluster_certificate),
            bootstrap_token: Some(config.bootstrap_token),
            cluster_domain: config.cluster_domain,
            cluster_dns_ip: config.cluster_dns_ip,
            node_labels: config.node_labels,
            node_taints: config.node_taints,
            max_pods: config.max_pods,
            cloud_provider: config.cloud_provider,
            static_pods: config.static_pods,
            kube_reserved: config.kube_reserved,
            system_reserved: config.system_reserved,
            eviction_hard: config.eviction_hard,
            image_gc_high_threshold_percent: config.image_gc.high_threshold_percent,
            image_gc_low_threshold_percent: config.image_gc.low_threshold_percent,
            image_minimum_gc_age: config.image_gc.minimum_age,
            image_maximum_gc_age: config.image_gc.maximum_age,
        }
    }
}

/// kubelet refuses to start with a `kubernetes.io` or `k8s.io` label it may not set itself
/// (`IsKubeletLabel` in `k8s.io/kubelet`).
fn kubelet_may_set(key: &QualifiedName) -> bool {
    const LABELS: &[&str] = &[
        "kubernetes.io/hostname",
        "kubernetes.io/os",
        "kubernetes.io/arch",
        "topology.kubernetes.io/zone",
        "topology.kubernetes.io/region",
        "failure-domain.beta.kubernetes.io/zone",
        "failure-domain.beta.kubernetes.io/region",
        "beta.kubernetes.io/instance-type",
        "node.kubernetes.io/instance-type",
        "beta.kubernetes.io/os",
        "beta.kubernetes.io/arch",
    ];
    let in_namespace = |namespace: &str, suffix: &str| {
        namespace == suffix || namespace.strip_suffix(suffix).is_some_and(|rest| rest.ends_with('.'))
    };
    let Some(namespace) = key.prefix() else {
        return true;
    };
    let restricted = in_namespace(namespace, "kubernetes.io") || in_namespace(namespace, "k8s.io");
    !restricted
        || LABELS.contains(&key.as_str())
        || in_namespace(namespace, "kubelet.kubernetes.io")
        || in_namespace(namespace, "node.kubernetes.io")
}

validated_string!(
    /// The API server's URL: `https://<host>[:<port>]`, with no path.
    ApiServerUrl,
    "API server URL",
    |url| {
        let uri: http::Uri = url.parse().map_err(|_| "is not a URL")?;
        let authority = uri.authority().ok_or("must name a host")?;
        if uri.scheme_str() != Some("https") {
            Err("must be https")
        } else if authority.as_str().contains('@') {
            Err("must not hold credentials")
        } else if !matches!(uri.path(), "" | "/") || uri.query().is_some() {
            Err("must have no path or query")
        } else {
            Ok(())
        }
    }
);

validated_string!(
    /// A Kubernetes qualified name (label and taint keys): `[<DNS subdomain>/]<name>`.
    QualifiedName,
    "label or taint key",
    |key| {
        let (prefix, name) = match key.split_once('/') {
            Some((prefix, name)) => (Some(prefix), name),
            None => (None, key),
        };
        if prefix.is_some_and(|prefix| !is_dns_subdomain(prefix)) {
            Err("its prefix must be a lowercase DNS subdomain")
        } else if name.is_empty() || !is_label_value(name) {
            Err("its name must be 1-63 alphanumerics, '-', '_' or '.', starting and ending with an alphanumeric")
        } else {
            Ok(())
        }
    }
);

impl QualifiedName {
    fn prefix(&self) -> Option<&str> {
        self.as_str().split_once('/').map(|(prefix, _)| prefix)
    }
}

validated_string!(
    /// A label value: empty, or 1-63 alphanumerics, '-', '_' or '.', starting and ending with an
    /// alphanumeric.
    LabelValue,
    "label value",
    |value| {
        if value.is_empty() || is_label_value(value) {
            Ok(())
        } else {
            Err("must be at most 63 alphanumerics, '-', '_' or '.', starting and ending with an alphanumeric")
        }
    }
);

fn is_label_value(value: &str) -> bool {
    let edges_alphanumeric =
        value.starts_with(|c: char| c.is_ascii_alphanumeric()) && value.ends_with(|c: char| c.is_ascii_alphanumeric());
    value.len() <= 63
        && edges_alphanumeric
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn is_dns_subdomain(name: &str) -> bool {
    let label = |label: &str| {
        !label.is_empty()
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    name.len() <= 253 && name.split('.').all(label)
}

/// A taint's value and effect, written `<value>:<effect>` (Bottlerocket's form); the value may
/// be empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TaintValue {
    pub value: LabelValue,
    pub effect: TaintEffect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

impl TaintEffect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoSchedule => "NoSchedule",
            Self::PreferNoSchedule => "PreferNoSchedule",
            Self::NoExecute => "NoExecute",
        }
    }
}

impl TryFrom<String> for TaintValue {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let reject = |reason| InvalidValue::new("taint", &text, reason);
        let (value, effect) = text
            .rsplit_once(':')
            .ok_or_else(|| reject("must be <value>:<effect>"))?;
        let effect = match effect {
            "NoSchedule" => TaintEffect::NoSchedule,
            "PreferNoSchedule" => TaintEffect::PreferNoSchedule,
            "NoExecute" => TaintEffect::NoExecute,
            _ => return Err(reject("its effect must be NoSchedule, PreferNoSchedule or NoExecute")),
        };
        Ok(Self {
            value: value.to_owned().try_into()?,
            effect,
        })
    }
}

impl From<TaintValue> for String {
    fn from(taint: TaintValue) -> Self {
        format!("{}:{}", taint.value, taint.effect.as_str())
    }
}

/// `[settings.kubernetes.static-pods.<name>]` (Bottlerocket's keys).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct StaticPod {
    #[serde(default = "enabled_by_default")]
    pub enabled: bool,
    pub manifest: PodManifest,
}

fn enabled_by_default() -> bool {
    true
}

/// A Pod manifest, YAML or JSON; base64-encoded in settings.
///
/// Checked without a YAML parser: a JSON manifest is parsed, a YAML one only scanned at its top
/// level (one document, `apiVersion: v1`, `kind: Pod`, `metadata`). That catches a manifest of the
/// wrong kind or a non-manifest; kubelet validates the rest, and reports it in its log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PodManifest(String);

impl PodManifest {
    const KIND: &str = "static pod manifest";

    pub fn text(&self) -> &str {
        &self.0
    }

    fn check(text: &str) -> Result<(), &'static str> {
        if text.contains('\0') {
            return Err("must not contain NUL bytes");
        }
        let (api_version, kind, has_metadata) = if text.trim_start().starts_with('{') {
            let manifest: serde_json::Value = serde_json::from_str(text).map_err(|_| "is not valid JSON")?;
            let field = |key: &str| manifest.get(key).and_then(serde_json::Value::as_str).map(str::to_owned);
            (
                field("apiVersion"),
                field("kind"),
                manifest.get("metadata").is_some_and(|m| m.is_object()),
            )
        } else {
            let keys = yaml_top_level(text)?;
            let field = |key: &str| keys.get(key).map(|value| (*value).to_owned());
            (field("apiVersion"), field("kind"), keys.contains_key("metadata"))
        };
        match (api_version.as_deref(), kind.as_deref()) {
            (Some("v1"), Some("Pod")) if has_metadata => Ok(()),
            (Some("v1"), Some("Pod")) => Err("has no metadata"),
            _ => Err("must be a Pod (apiVersion: v1, kind: Pod)"),
        }
    }
}

/// The top-level `key: value` pairs of a YAML mapping document (a nested value is empty).
fn yaml_top_level(text: &str) -> Result<BTreeMap<&str, &str>, &'static str> {
    let mut keys = BTreeMap::new();
    for line in text.lines() {
        let content = line.trim_end();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        if content == "---" || content == "..." {
            if keys.is_empty() {
                continue;
            }
            return Err("must hold a single YAML document");
        }
        // Lines of nested values (indented, or block sequence items).
        if line.starts_with([' ', '\t', '-']) {
            if keys.is_empty() {
                return Err("must be a YAML mapping");
            }
            continue;
        }
        let (key, value) = content.split_once(':').ok_or("must be a YAML mapping")?;
        let value = value.split(" #").next().unwrap_or_default().trim();
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        if keys.insert(key.trim(), value).is_some() {
            return Err("has a key twice");
        }
    }
    Ok(keys)
}

impl TryFrom<String> for PodManifest {
    type Error = InvalidValue;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        let reject = |reason| InvalidValue::new(Self::KIND, "<base64>", reason);
        let bytes = crate::types::decode_base64(encoded.as_bytes()).ok_or_else(|| reject("is not base64"))?;
        let text = String::from_utf8(bytes).map_err(|_| reject("is not UTF-8 text"))?;
        Self::check(&text).map_err(reject)?;
        Ok(Self(text))
    }
}

/// To the base64 of the manifest.
impl From<PodManifest> for String {
    fn from(manifest: PodManifest) -> Self {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(manifest.0)
    }
}

/// A bootstrap token, `<id>.<secret>` (6 and 16 lowercase alphanumerics). Like [`PrivateKey`],
/// never displayed, logged or serialized.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct BootstrapToken(String);

impl BootstrapToken {
    /// The token, to write kubelet's bootstrap kubeconfig. The only way to read it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BootstrapToken {
    type Error = InvalidValue;

    fn try_from(token: String) -> Result<Self, Self::Error> {
        let part =
            |text: &str, len| text.len() == len && text.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        match token.split_once('.') {
            Some((id, secret)) if part(id, 6) && part(secret, 16) => Ok(Self(token)),
            _ => Err(InvalidValue::new(
                "bootstrap token",
                PrivateKey::REDACTED,
                "must be <6 lowercase alphanumerics>.<16 lowercase alphanumerics>",
            )),
        }
    }
}

impl Serialize for BootstrapToken {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(PrivateKey::REDACTED)
    }
}

impl fmt::Debug for BootstrapToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PrivateKey::REDACTED)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_server_urls() {
        for good in [
            "https://k8s.example.com",
            "https://192.0.2.1:6443",
            "https://[2001:db8::1]:6443/",
        ] {
            assert!(good.parse::<ApiServerUrl>().is_ok(), "{good}");
        }
        for bad in [
            "http://k8s.example.com",
            "k8s.example.com:6443",
            "https://user:pw@k8s.example.com",
            "https://k8s.example.com/api",
            "https://k8s.example.com?x=1",
            "https://k8s example.com",
        ] {
            assert!(bad.parse::<ApiServerUrl>().is_err(), "{bad}");
        }
    }

    #[test]
    fn label_keys_and_values() {
        for good in ["app", "example.com/role", "a.b-c/x_y.z", "node.kubernetes.io/pool"] {
            assert!(good.parse::<QualifiedName>().is_ok(), "{good}");
        }
        for bad in ["", "/x", "Example.com/x", "a/b/c", "-x", "x-", &"a".repeat(64), "a b"] {
            assert!(bad.parse::<QualifiedName>().is_err(), "{bad:?}");
        }
        for good in ["", "v1", "a.b_c-d"] {
            assert!(good.parse::<LabelValue>().is_ok(), "{good:?}");
        }
        for bad in ["-a", "a,b", "a=b", &"a".repeat(64)] {
            assert!(bad.parse::<LabelValue>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn kubelet_label_namespaces() {
        let may_set = |key: &str| kubelet_may_set(&key.parse().unwrap());
        for allowed in [
            "role",
            "example.com/role",
            "node.kubernetes.io/pool",
            "pool.node.kubernetes.io/x",
            "kubelet.kubernetes.io/x",
            "topology.kubernetes.io/zone",
            "notkubernetes.io/x",
        ] {
            assert!(may_set(allowed), "{allowed}");
        }
        for denied in [
            "node-role.kubernetes.io/worker",
            "kubernetes.io/role",
            "x.k8s.io/y",
            "node-restriction.kubernetes.io/x",
        ] {
            assert!(!may_set(denied), "{denied}");
        }
    }

    #[test]
    fn taints() {
        let taint: TaintValue = "gpu:NoSchedule".to_owned().try_into().unwrap();
        assert_eq!((taint.value.as_str(), taint.effect), ("gpu", TaintEffect::NoSchedule));
        let empty: TaintValue = ":NoExecute".to_owned().try_into().unwrap();
        assert_eq!(empty.value.as_str(), "");
        assert_eq!(String::from(empty), ":NoExecute");
        for bad in ["gpu", "gpu:Never", "a b:NoSchedule"] {
            assert!(TaintValue::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    fn manifest(text: &str) -> Result<PodManifest, InvalidValue> {
        use base64::Engine;
        PodManifest::try_from(base64::engine::general_purpose::STANDARD.encode(text))
    }

    #[test]
    fn pod_manifests() {
        let yaml = "# A static pod.\n---\napiVersion: v1\nkind: \"Pod\"  # quoted\nmetadata:\n  name: web\n\
                    spec:\n  containers:\n  - name: web\n    image: nginx\n    args: |\n      kind: Deployment\n";
        assert_eq!(manifest(yaml).unwrap().text(), yaml);
        let json = r#"{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "web"}, "spec": {}}"#;
        assert!(manifest(json).is_ok());
        assert_eq!(String::from(manifest(json).unwrap()), {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(json)
        });
        for (bad, why) in [
            ("apiVersion: apps/v1\nkind: Deployment\nmetadata: {}\n", "a Deployment"),
            ("apiVersion: v1\nkind: Pod\n", "no metadata"),
            (
                "apiVersion: v1\nkind: Pod\nmetadata: {}\n---\napiVersion: v1\nkind: Pod\n",
                "two documents",
            ),
            ("apiVersion: v1\nkind: Pod\nkind: Pod\nmetadata: {}\n", "a key twice"),
            ("- apiVersion: v1\n", "a sequence"),
            ("just text\n", "not a mapping"),
            (r#"{"apiVersion": "v1", "kind": "Pod""#, "truncated JSON"),
            (
                r#"{"apiVersion": "v1", "kind": "Service", "metadata": {}}"#,
                "a JSON Service",
            ),
        ] {
            assert!(manifest(bad).is_err(), "{why} accepted");
        }
        assert!(PodManifest::try_from("not base64!".to_owned()).is_err());
    }

    #[test]
    fn bootstrap_tokens_are_never_shown() {
        let token = BootstrapToken::try_from("abcdef.0123456789abcdef".to_owned()).unwrap();
        assert_eq!(token.expose(), "abcdef.0123456789abcdef");
        assert_eq!(format!("{token:?}"), PrivateKey::REDACTED);
        assert_eq!(serde_json::to_string(&token).unwrap(), "\"<redacted>\"");
        for bad in [
            "abcdef",
            "abcde.0123456789abcdef",
            "ABCDEF.0123456789abcdef",
            "abcdef.0123456789abcdeF",
        ] {
            let error = BootstrapToken::try_from(bad.to_owned()).unwrap_err();
            assert!(!error.to_string().contains("0123"), "the token is not echoed");
        }
    }
}

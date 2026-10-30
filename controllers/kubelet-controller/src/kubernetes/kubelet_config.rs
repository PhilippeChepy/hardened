//! `[settings.kubernetes]` itself: kubelet's configuration.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::num::NonZeroU16;

use controllers_helpers::{Certificates, DomainName, WorkloadName};
use serde::{Deserialize, Serialize};

use super::api_server_url::ApiServerUrl;
use super::bootstrap_token::BootstrapToken;
use super::image_gc::{ImageAges, ImageGc, Percent, ThresholdPercents};
use super::labels::{LabelValue, NodeLabelKey, QualifiedName};
use super::pod_grace_period::PodGracePeriod;
use super::resources::{Duration, EvictionSignal, Quantity, ReservedResource, Threshold};
use super::soft_eviction::SoftEviction;
use super::static_pod::StaticPod;
use super::taint_value::TaintValue;

/// `[settings.kubernetes]`, kubelet's configuration: what it needs to join a cluster (the API
/// server, its CA and a bootstrap token), and its node's settings.
///
/// Written with Bottlerocket's keys: soft eviction thresholds and their grace periods
/// in two tables paired by signal ([`SoftEviction`]), image garbage collection in four keys
/// ([`ImageGc`]), `cluster-dns-ip` as one address or a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Keys", into = "Keys")]
pub struct KubeletConfig {
    /// The cluster's API server.
    pub api_server: ApiServerUrl,
    /// The cluster CA: the API server's certificate chains to it, and so do the client
    /// certificates kubelet's own API accepts.
    pub cluster_certificate: Certificates,
    /// TLS bootstrapping: kubelet requests its client certificate with it, then rotates it.
    pub bootstrap_token: BootstrapToken,
    /// The cluster's DNS domain.
    pub cluster_domain: DomainName,
    /// The cluster DNS service, which pods resolve with.
    pub cluster_dns_ip: Vec<IpAddr>,
    /// The labels kubelet registers the node with.
    pub node_labels: BTreeMap<NodeLabelKey, LabelValue>,
    /// The taints kubelet registers the node with, by key.
    pub node_taints: BTreeMap<QualifiedName, Vec<TaintValue>>,
    /// The most pods the node runs.
    pub max_pods: Option<NonZeroU16>,
    /// What initializes the node, when not kubelet itself.
    pub cloud_provider: Option<CloudProvider>,
    /// Pods kubelet runs from files, without the API server; by file name.
    pub static_pods: BTreeMap<WorkloadName, StaticPod>,
    /// Resources reserved for Kubernetes daemons.
    pub kube_reserved: BTreeMap<ReservedResource, Quantity>,
    /// Resources reserved for the system.
    pub system_reserved: BTreeMap<ReservedResource, Quantity>,
    /// Replaces kubelet's defaults as a whole: a signal left out is not checked.
    pub eviction_hard: BTreeMap<EvictionSignal, Threshold>,
    /// Thresholds below which kubelet evicts pods once they last their grace period.
    pub eviction_soft: BTreeMap<EvictionSignal, SoftEviction>,
    /// The longest a pod evicted on a soft threshold gets to stop.
    pub eviction_max_pod_grace_period: Option<PodGracePeriod>,
    /// Image garbage collection.
    pub image_gc: ImageGc,
}

/// `[settings.kubernetes]` as written: Bottlerocket's flat keys, converted from and to
/// [`KubeletConfig`].
#[derive(Deserialize, Serialize)]
#[serde(
    rename_all = "kebab-case",
    deny_unknown_fields,
    expecting = "the table of settings.kubernetes"
)]
struct Keys {
    api_server: ApiServerUrl,
    cluster_certificate: Certificates,
    bootstrap_token: BootstrapToken,
    #[serde(default = "default_cluster_domain")]
    cluster_domain: DomainName,
    cluster_dns_ip: Option<IpAddrs>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    node_labels: BTreeMap<NodeLabelKey, LabelValue>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    node_taints: BTreeMap<QualifiedName, Vec<TaintValue>>,
    max_pods: Option<NonZeroU16>,
    cloud_provider: Option<CloudProvider>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    static_pods: BTreeMap<WorkloadName, StaticPod>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    kube_reserved: BTreeMap<ReservedResource, Quantity>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    system_reserved: BTreeMap<ReservedResource, Quantity>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    eviction_hard: BTreeMap<EvictionSignal, Threshold>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    eviction_soft: BTreeMap<EvictionSignal, Threshold>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    eviction_soft_grace_period: BTreeMap<EvictionSignal, Duration>,
    eviction_max_pod_grace_period: Option<PodGracePeriod>,
    image_gc_high_threshold_percent: Option<Percent>,
    image_gc_low_threshold_percent: Option<Percent>,
    image_minimum_gc_age: Option<Duration>,
    image_maximum_gc_age: Option<Duration>,
}

/// `cluster-dns-ip`: one address, or a list.
#[derive(Deserialize, Serialize)]
#[serde(untagged, expecting = "an IP address, or a list of them")]
enum IpAddrs {
    One(IpAddr),
    Many(Vec<IpAddr>),
}

/// Pairs the soft evictions and image GC keys, rejecting what kubelet would.
impl TryFrom<Keys> for KubeletConfig {
    type Error = String;

    fn try_from(keys: Keys) -> Result<Self, Self::Error> {
        Ok(Self {
            api_server: keys.api_server,
            cluster_certificate: keys.cluster_certificate,
            bootstrap_token: keys.bootstrap_token,
            cluster_domain: keys.cluster_domain,
            cluster_dns_ip: match keys.cluster_dns_ip {
                None => Vec::new(),
                Some(IpAddrs::One(ip)) => vec![ip],
                Some(IpAddrs::Many(ips)) => ips,
            },
            node_labels: keys.node_labels,
            node_taints: keys.node_taints,
            max_pods: keys.max_pods,
            cloud_provider: keys.cloud_provider,
            static_pods: keys.static_pods,
            kube_reserved: keys.kube_reserved,
            system_reserved: keys.system_reserved,
            eviction_hard: keys.eviction_hard,
            eviction_soft: SoftEviction::pair(keys.eviction_soft, keys.eviction_soft_grace_period)?,
            eviction_max_pod_grace_period: keys.eviction_max_pod_grace_period,
            image_gc: ImageGc::from_keys(
                keys.image_gc_high_threshold_percent,
                keys.image_gc_low_threshold_percent,
                keys.image_minimum_gc_age,
                keys.image_maximum_gc_age,
            )?,
        })
    }
}

impl From<KubeletConfig> for Keys {
    fn from(config: KubeletConfig) -> Self {
        let (eviction_soft, eviction_soft_grace_period) = config
            .eviction_soft
            .into_iter()
            .map(|(signal, soft)| ((signal, soft.threshold), (signal, soft.grace_period)))
            .unzip();
        let thresholds = config.image_gc.threshold_percent;
        let ages = config.image_gc.age;
        Self {
            api_server: config.api_server,
            cluster_certificate: config.cluster_certificate,
            bootstrap_token: config.bootstrap_token,
            cluster_domain: config.cluster_domain,
            cluster_dns_ip: match <[IpAddr; 1]>::try_from(config.cluster_dns_ip) {
                Ok([ip]) => Some(IpAddrs::One(ip)),
                Err(ips) if ips.is_empty() => None,
                Err(ips) => Some(IpAddrs::Many(ips)),
            },
            node_labels: config.node_labels,
            node_taints: config.node_taints,
            max_pods: config.max_pods,
            cloud_provider: config.cloud_provider,
            static_pods: config.static_pods,
            kube_reserved: config.kube_reserved,
            system_reserved: config.system_reserved,
            eviction_hard: config.eviction_hard,
            eviction_soft,
            eviction_soft_grace_period,
            eviction_max_pod_grace_period: config.eviction_max_pod_grace_period,
            image_gc_high_threshold_percent: thresholds.map(ThresholdPercents::high),
            image_gc_low_threshold_percent: thresholds.map(ThresholdPercents::low),
            image_minimum_gc_age: ages.map(ImageAges::minimum),
            image_maximum_gc_age: ages.and_then(ImageAges::maximum),
        }
    }
}

/// What initializes the node.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CloudProvider {
    /// A cloud controller manager initializes the node (kubelet's `--cloud-provider=external`).
    External,
}

/// The cluster domain when `cluster-domain` is left out: `cluster.local`.
#[must_use]
pub(crate) fn default_cluster_domain() -> DomainName {
    "cluster.local".parse().expect("a valid domain name")
}

#[cfg(test)]
mod tests {
    use controllers_helpers::base64_text;
    use controllers_helpers::testing;

    use super::*;
    use crate::testing::full_toml;

    /// `[settings.kubernetes]`, with `extra` keys.
    fn kubernetes(extra: &str) -> Result<KubeletConfig, toml::de::Error> {
        let (certificate, _) = testing::certificate_and_key();
        let certificate = base64_text::encode(certificate);
        toml::from_str(&format!(
            "api-server = \"https://k8s.example.com:6443\"\n\
             cluster-certificate = \"{certificate}\"\n\
             bootstrap-token = \"abcdef.0123456789abcdef\"\n{extra}\n"
        ))
    }

    fn rejected(extra: &str) -> String {
        kubernetes(extra).unwrap_err().to_string()
    }

    #[test]
    fn defaults() {
        let config = kubernetes("").unwrap();
        assert_eq!(config.cluster_domain.as_str(), "cluster.local");
        assert_eq!(config.image_gc, ImageGc::default());
    }

    #[test]
    fn round_trips_with_the_bootstrap_token() {
        let config: KubeletConfig = toml::from_str(&full_toml()).unwrap();
        let text = toml::to_string(&config).unwrap();
        assert!(text.contains("abcdef.0123456789abcdef"), "{text}");
        assert_eq!(
            toml::from_str::<KubeletConfig>(&text).unwrap(),
            config,
            "{text}"
        );
        let json = serde_json::to_string(&config).unwrap();
        assert_eq!(
            serde_json::from_str::<KubeletConfig>(&json).unwrap(),
            config
        );
    }

    #[test]
    fn cluster_dns_takes_one_address_or_a_list() {
        let one = kubernetes("cluster-dns-ip = \"10.96.0.10\"").unwrap();
        assert_eq!(one.cluster_dns_ip.len(), 1);
        let text = toml::to_string(&one).unwrap();
        assert!(text.contains("cluster-dns-ip = \"10.96.0.10\""), "{text}");
        let both = kubernetes("cluster-dns-ip = [\"10.96.0.10\", \"fd00::a\"]").unwrap();
        assert_eq!(both.cluster_dns_ip.len(), 2);
        assert!(kubernetes("cluster-dns-ip = \"kube-dns\"").is_err());
    }

    #[test]
    fn soft_evictions_pair_by_signal() {
        let config = kubernetes(
            "eviction-soft = { \"memory.available\" = \"10%\" }\n\
             eviction-soft-grace-period = { \"memory.available\" = \"1m30s\" }",
        )
        .unwrap();
        let soft = &config.eviction_soft[&EvictionSignal::MemoryAvailable];
        assert_eq!(soft.threshold.as_str(), "10%");
        assert_eq!(soft.grace_period.millis(), 90_000);
    }

    #[test]
    fn image_gc_takes_numbers_or_strings_and_kubelet_defaults() {
        let config =
            kubernetes("image-gc-high-threshold-percent = \"90\"\nimage-maximum-gc-age = \"168h\"")
                .unwrap();
        let thresholds = config.image_gc.threshold_percent.unwrap();
        assert_eq!((thresholds.low().get(), thresholds.high().get()), (80, 90));
        let ages = config.image_gc.age.unwrap();
        assert_eq!(ages.minimum().to_string(), "2m");
        assert_eq!(
            ages.maximum().map(|age| age.to_string()),
            Some("168h".into())
        );
        let off = kubernetes("image-maximum-gc-age = \"0s\"").unwrap();
        assert_eq!(
            off.image_gc,
            ImageGc::default(),
            "0 turns the maximum age off"
        );
    }

    #[test]
    fn rejects_a_missing_cluster_key() {
        let (certificate, _) = testing::certificate_and_key();
        let certificate = base64_text::encode(certificate);
        for (document, key) in [
            (
                format!(
                    "cluster-certificate = \"{certificate}\"\nbootstrap-token = \"abcdef.0123456789abcdef\""
                ),
                "api-server",
            ),
            (
                "api-server = \"https://k8s\"\nbootstrap-token = \"abcdef.0123456789abcdef\""
                    .to_owned(),
                "cluster-certificate",
            ),
            (
                format!("api-server = \"https://k8s\"\ncluster-certificate = \"{certificate}\""),
                "bootstrap-token",
            ),
        ] {
            let error = toml::from_str::<KubeletConfig>(&document).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains(&format!("missing field `{key}`")),
                "{error}"
            );
        }
    }

    #[test]
    fn rejects_a_node_label_kubelet_may_not_set() {
        let error = rejected("node-labels = { \"node-role.kubernetes.io/worker\" = \"\" }");
        assert!(error.contains("node-role.kubernetes.io/worker"), "{error}");
    }

    #[test]
    fn rejects_a_soft_threshold_without_grace_period() {
        let error = rejected("eviction-soft = { \"memory.available\" = \"10%\" }");
        assert!(
            error.contains("needs its eviction-soft-grace-period"),
            "{error}"
        );
    }

    #[test]
    fn rejects_a_grace_period_without_soft_threshold() {
        let error = rejected("eviction-soft-grace-period = { \"memory.available\" = \"1m\" }");
        assert!(error.contains("has no eviction-soft threshold"), "{error}");
    }

    #[test]
    fn rejects_a_low_image_gc_threshold_not_below_the_high_one() {
        for extra in [
            "image-gc-high-threshold-percent = 70\nimage-gc-low-threshold-percent = 90",
            "image-gc-high-threshold-percent = 60\nimage-gc-low-threshold-percent = \"60\"",
            "image-gc-low-threshold-percent = 90",
        ] {
            assert!(rejected(extra).contains("must be below"), "{extra}");
        }
    }

    #[test]
    fn rejects_a_percentage_above_100() {
        for extra in [
            "image-gc-high-threshold-percent = 101",
            "image-gc-high-threshold-percent = \"x\"",
        ] {
            assert!(rejected(extra).contains("from 0 to 100"), "{extra}");
        }
    }

    #[test]
    fn rejects_a_maximum_image_age_not_above_the_minimum() {
        for extra in [
            "image-minimum-gc-age = \"1h\"\nimage-maximum-gc-age = \"1m\"",
            "image-maximum-gc-age = \"1m\"",
        ] {
            assert!(rejected(extra).contains("must be above"), "{extra}");
        }
    }

    #[test]
    fn rejects_unknown_keys() {
        for extra in [
            "enabled = true",
            "image-gc = { threshold-percent = [70, 90] }",
        ] {
            assert!(rejected(extra).contains("unknown field"), "{extra}");
        }
    }
}

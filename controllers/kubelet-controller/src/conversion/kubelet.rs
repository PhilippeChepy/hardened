//! `settings.kubernetes` as kubelet-controller's `Kubelet` message.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::net::IpAddr;
use std::num::NonZeroU16;

use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::{FieldResult, WithinResult};
use controllers_helpers::{Certificates, DomainName, InvalidMessage, WorkloadName};

use crate::kubelet;
use crate::kubelet::threshold;
use crate::kubernetes;
use crate::{
    ApiServerUrl, BootstrapToken, CloudProvider, Duration, EvictionSignal, ImageAges, ImageGc,
    KubeletConfig, LabelValue, NodeLabelKey, Percent, PodGracePeriod, PodManifest, QualifiedName,
    Quantity, ReservedResource, SoftEviction, StaticPod, TaintEffect, TaintValue, Threshold,
    ThresholdPercents,
};

impl From<ReservedResource> for kubelet::Resource {
    fn from(resource: ReservedResource) -> Self {
        match resource {
            ReservedResource::Cpu => Self::Cpu,
            ReservedResource::Memory => Self::Memory,
            ReservedResource::EphemeralStorage => Self::EphemeralStorage,
            ReservedResource::Pid => Self::Pid,
        }
    }
}

impl From<EvictionSignal> for kubelet::EvictionSignal {
    fn from(signal: EvictionSignal) -> Self {
        match signal {
            EvictionSignal::MemoryAvailable => Self::MemoryAvailable,
            EvictionSignal::NodefsAvailable => Self::NodefsAvailable,
            EvictionSignal::NodefsInodesFree => Self::NodefsInodesFree,
            EvictionSignal::ImagefsAvailable => Self::ImagefsAvailable,
            EvictionSignal::ImagefsInodesFree => Self::ImagefsInodesFree,
            EvictionSignal::PidAvailable => Self::PidAvailable,
        }
    }
}

impl From<TaintEffect> for kubelet::TaintEffect {
    fn from(effect: TaintEffect) -> Self {
        match effect {
            TaintEffect::NoSchedule => Self::NoSchedule,
            TaintEffect::PreferNoSchedule => Self::PreferNoSchedule,
            TaintEffect::NoExecute => Self::NoExecute,
        }
    }
}

/// Fails on `Unspecified`.
impl TryFrom<kubelet::Resource> for ReservedResource {
    type Error = InvalidMessage;

    fn try_from(resource: kubelet::Resource) -> Result<Self, Self::Error> {
        match resource {
            kubelet::Resource::Cpu => Ok(Self::Cpu),
            kubelet::Resource::Memory => Ok(Self::Memory),
            kubelet::Resource::EphemeralStorage => Ok(Self::EphemeralStorage),
            kubelet::Resource::Pid => Ok(Self::Pid),
            kubelet::Resource::Unspecified => Err(unspecified()),
        }
    }
}

/// Fails on `Unspecified`.
impl TryFrom<kubelet::EvictionSignal> for EvictionSignal {
    type Error = InvalidMessage;

    fn try_from(signal: kubelet::EvictionSignal) -> Result<Self, Self::Error> {
        match signal {
            kubelet::EvictionSignal::MemoryAvailable => Ok(Self::MemoryAvailable),
            kubelet::EvictionSignal::NodefsAvailable => Ok(Self::NodefsAvailable),
            kubelet::EvictionSignal::NodefsInodesFree => Ok(Self::NodefsInodesFree),
            kubelet::EvictionSignal::ImagefsAvailable => Ok(Self::ImagefsAvailable),
            kubelet::EvictionSignal::ImagefsInodesFree => Ok(Self::ImagefsInodesFree),
            kubelet::EvictionSignal::PidAvailable => Ok(Self::PidAvailable),
            kubelet::EvictionSignal::Unspecified => Err(unspecified()),
        }
    }
}

/// Fails on `Unspecified`.
impl TryFrom<kubelet::TaintEffect> for TaintEffect {
    type Error = InvalidMessage;

    fn try_from(effect: kubelet::TaintEffect) -> Result<Self, Self::Error> {
        match effect {
            kubelet::TaintEffect::NoSchedule => Ok(Self::NoSchedule),
            kubelet::TaintEffect::PreferNoSchedule => Ok(Self::PreferNoSchedule),
            kubelet::TaintEffect::NoExecute => Ok(Self::NoExecute),
            kubelet::TaintEffect::Unspecified => Err(unspecified()),
        }
    }
}

fn unspecified() -> InvalidMessage {
    InvalidMessage::whole("must be set")
}

/// The domain value of `value`, the proto enum `P` of `field`.
fn enum_value<P, D>(value: i32, field: &str) -> Result<D, InvalidMessage>
where
    P: TryFrom<i32>,
    D: TryFrom<P, Error = InvalidMessage>,
{
    P::try_from(value)
        .map_err(|_| unspecified())
        .and_then(D::try_from)
        .within(field)
}

/// A percentage becomes a `double`, which formats back the same unless written with superfluous
/// zeros (`15.0%` comes back as `15%`).
impl From<Threshold> for kubelet::Threshold {
    fn from(threshold: Threshold) -> Self {
        let value = match threshold.as_str().strip_suffix('%') {
            Some(percent) => threshold::Threshold::Percent(
                percent.parse().expect("a validated percentage is a number"),
            ),
            None => threshold::Threshold::Quantity(threshold.into()),
        };
        Self {
            threshold: Some(value),
        }
    }
}

impl TryFrom<kubelet::Threshold> for Threshold {
    type Error = InvalidMessage;

    fn try_from(message: kubelet::Threshold) -> Result<Self, Self::Error> {
        match invalid_message::required(message.threshold, "threshold")? {
            threshold::Threshold::Quantity(quantity) => {
                let quantity = Quantity::try_from(quantity).field("quantity")?;
                Threshold::try_from(String::from(quantity)).field("quantity")
            }
            // Rust formats a float without an exponent, as a threshold has it.
            threshold::Threshold::Percent(percent) => {
                Threshold::try_from(format!("{percent}%")).field("percent")
            }
        }
    }
}

impl From<ImageGc> for kubelet::ImageGc {
    fn from(image_gc: ImageGc) -> Self {
        Self {
            threshold_percent: image_gc.threshold_percent.map(|thresholds| {
                kubelet::ThresholdPercents {
                    low: thresholds.low().get().into(),
                    high: thresholds.high().get().into(),
                }
            }),
            age: image_gc.age.map(|ages| kubelet::ImageAges {
                minimum: Some(ages.minimum().into()),
                maximum: ages.maximum().map(prost_types::Duration::from),
            }),
        }
    }
}

impl TryFrom<kubelet::ThresholdPercents> for ThresholdPercents {
    type Error = InvalidMessage;

    fn try_from(message: kubelet::ThresholdPercents) -> Result<Self, Self::Error> {
        let percent = |value: u32, field| Percent::try_from(u64::from(value)).field(field);
        Self::new(percent(message.low, "low")?, percent(message.high, "high")?)
            .map_err(InvalidMessage::whole)
    }
}

impl TryFrom<kubelet::ImageAges> for ImageAges {
    type Error = InvalidMessage;

    fn try_from(message: kubelet::ImageAges) -> Result<Self, Self::Error> {
        let minimum = invalid_message::required(message.minimum, "minimum")?;
        Self::new(
            Duration::try_from(minimum).field("minimum")?,
            message
                .maximum
                .map(Duration::try_from)
                .transpose()
                .field("maximum")?,
        )
        .map_err(InvalidMessage::whole)
    }
}

impl TryFrom<kubelet::ImageGc> for ImageGc {
    type Error = InvalidMessage;

    fn try_from(message: kubelet::ImageGc) -> Result<Self, Self::Error> {
        Ok(Self {
            threshold_percent: message
                .threshold_percent
                .map(ThresholdPercents::try_from)
                .transpose()
                .within("threshold_percent")?,
            age: message
                .age
                .map(ImageAges::try_from)
                .transpose()
                .within("age")?,
        })
    }
}

/// The secrets included. Taints are flattened, one per key and value.
impl From<KubeletConfig> for kubelet::Kubelet {
    fn from(config: KubeletConfig) -> Self {
        let reservations = |reserved: BTreeMap<ReservedResource, Quantity>| {
            reserved
                .into_iter()
                .map(|(resource, quantity)| kubelet::Reservation {
                    resource: kubelet::Resource::from(resource).into(),
                    quantity: quantity.into(),
                })
                .collect()
        };
        Self {
            api_server: config.api_server.into(),
            cluster_certificate: config.cluster_certificate.pem().to_owned(),
            bootstrap_token: config.bootstrap_token.expose().to_owned(),
            cluster_domain: config.cluster_domain.into(),
            cluster_dns_ip: config
                .cluster_dns_ip
                .iter()
                .map(IpAddr::to_string)
                .collect(),
            node_labels: config
                .node_labels
                .into_iter()
                .map(|(key, value)| (key.into(), value.into()))
                .collect(),
            node_taints: config
                .node_taints
                .into_iter()
                .flat_map(|(key, values)| {
                    values.into_iter().map(move |taint| kubelet::Taint {
                        key: key.to_string(),
                        value: taint.value.into(),
                        effect: kubelet::TaintEffect::from(taint.effect).into(),
                    })
                })
                .collect(),
            max_pods: config.max_pods.map(|max| max.get().into()),
            cloud_provider: match config.cloud_provider {
                None => kubelet::CloudProvider::Unspecified,
                Some(CloudProvider::External) => kubelet::CloudProvider::External,
            }
            .into(),
            static_pods: config
                .static_pods
                .into_iter()
                .map(|(name, pod)| kubelet::StaticPod {
                    name: name.into(),
                    enabled: pod.enabled,
                    manifest: pod.manifest.text().to_owned(),
                })
                .collect(),
            kube_reserved: reservations(config.kube_reserved),
            system_reserved: reservations(config.system_reserved),
            eviction_hard: config
                .eviction_hard
                .into_iter()
                .map(|(signal, threshold)| kubelet::HardEviction {
                    signal: kubelet::EvictionSignal::from(signal).into(),
                    threshold: Some(threshold.into()),
                })
                .collect(),
            eviction_soft: config
                .eviction_soft
                .into_iter()
                .map(|(signal, soft)| kubelet::SoftEviction {
                    signal: kubelet::EvictionSignal::from(signal).into(),
                    threshold: Some(soft.threshold.into()),
                    grace_period: Some(soft.grace_period.into()),
                })
                .collect(),
            eviction_max_pod_grace_period: config
                .eviction_max_pod_grace_period
                .map(prost_types::Duration::from),
            image_gc: Some(config.image_gc.into()),
        }
    }
}

/// Validated as `settings.kubernetes` is in user-data. An empty cluster domain
/// is the default, `cluster.local`.
impl TryFrom<kubelet::Kubelet> for KubeletConfig {
    type Error = InvalidMessage;

    fn try_from(message: kubelet::Kubelet) -> Result<Self, Self::Error> {
        let cluster_domain = if message.cluster_domain.is_empty() {
            kubernetes::default_cluster_domain()
        } else {
            DomainName::try_from(message.cluster_domain).field("cluster_domain")?
        };
        let cluster_dns_ip =
            invalid_message::convert_each(message.cluster_dns_ip, "cluster_dns_ip", |ip| {
                ip.parse::<IpAddr>()
            })?;
        let node_labels = message
            .node_labels
            .into_iter()
            .map(|(key, value)| {
                Ok((
                    NodeLabelKey::try_from(key).field("node_labels")?,
                    LabelValue::try_from(value).field("node_labels")?,
                ))
            })
            .collect::<Result<_, InvalidMessage>>()?;
        let max_pods = message
            .max_pods
            .map(|max| {
                u16::try_from(max)
                    .ok()
                    .and_then(NonZeroU16::new)
                    .ok_or("must be from 1 to 65535")
            })
            .transpose()
            .field("max_pods")?;
        let cloud_provider = match kubelet::CloudProvider::try_from(message.cloud_provider) {
            Ok(kubelet::CloudProvider::Unspecified) => None,
            Ok(kubelet::CloudProvider::External) => Some(CloudProvider::External),
            Err(error) => return Err(InvalidMessage::new("cloud_provider", error)),
        };
        Ok(Self {
            api_server: ApiServerUrl::try_from(message.api_server).field("api_server")?,
            cluster_certificate: Certificates::from_pem(message.cluster_certificate)
                .field("cluster_certificate")?,
            bootstrap_token: BootstrapToken::try_from(message.bootstrap_token)
                .field("bootstrap_token")?,
            cluster_domain,
            cluster_dns_ip,
            node_labels,
            node_taints: taints(message.node_taints)?,
            max_pods,
            cloud_provider,
            static_pods: static_pods(message.static_pods)?,
            kube_reserved: reservations(message.kube_reserved, "kube_reserved")?,
            system_reserved: reservations(message.system_reserved, "system_reserved")?,
            eviction_hard: hard_evictions(message.eviction_hard)?,
            eviction_soft: soft_evictions(message.eviction_soft)?,
            eviction_max_pod_grace_period: message
                .eviction_max_pod_grace_period
                .map(PodGracePeriod::try_from)
                .transpose()
                .field("eviction_max_pod_grace_period")?,
            image_gc: message
                .image_gc
                .map(ImageGc::try_from)
                .transpose()
                .within("image_gc")?
                .unwrap_or_default(),
        })
    }
}

/// Inserts `value` under `key`, rejecting a key given twice.
fn insert_once<K: Ord, V>(
    map: &mut BTreeMap<K, V>,
    key: K,
    value: V,
    field: &str,
) -> Result<(), InvalidMessage> {
    match map.entry(key) {
        Entry::Vacant(entry) => {
            entry.insert(value);
            Ok(())
        }
        Entry::Occupied(_) => Err(InvalidMessage::new(field, "given twice")),
    }
}

/// The taints, grouped by key in the order given.
fn taints(
    messages: Vec<kubelet::Taint>,
) -> Result<BTreeMap<QualifiedName, Vec<TaintValue>>, InvalidMessage> {
    let mut taints: BTreeMap<QualifiedName, Vec<TaintValue>> = BTreeMap::new();
    for (index, message) in messages.into_iter().enumerate() {
        let field = |name: &str| format!("node_taints[{index}].{name}");
        let effect =
            enum_value::<kubelet::TaintEffect, TaintEffect>(message.effect, &field("effect"))?;
        let key = QualifiedName::try_from(message.key).field(&field("key"))?;
        let value = LabelValue::try_from(message.value).field(&field("value"))?;
        taints
            .entry(key)
            .or_default()
            .push(TaintValue { value, effect });
    }
    Ok(taints)
}

fn static_pods(
    messages: Vec<kubelet::StaticPod>,
) -> Result<BTreeMap<WorkloadName, StaticPod>, InvalidMessage> {
    let mut pods = BTreeMap::new();
    for (index, message) in messages.into_iter().enumerate() {
        let field = |name: &str| format!("static_pods[{index}].{name}");
        let name = WorkloadName::try_from(message.name).field(&field("name"))?;
        let pod = StaticPod {
            enabled: message.enabled,
            manifest: PodManifest::from_text(message.manifest).field(&field("manifest"))?,
        };
        insert_once(&mut pods, name, pod, &field("name"))?;
    }
    Ok(pods)
}

fn reservations(
    messages: Vec<kubelet::Reservation>,
    field: &str,
) -> Result<BTreeMap<ReservedResource, Quantity>, InvalidMessage> {
    let mut reserved = BTreeMap::new();
    for (index, message) in messages.into_iter().enumerate() {
        let field = |name: &str| format!("{field}[{index}].{name}");
        let resource = enum_value::<kubelet::Resource, ReservedResource>(
            message.resource,
            &field("resource"),
        )?;
        let quantity = Quantity::try_from(message.quantity).field(&field("quantity"))?;
        insert_once(&mut reserved, resource, quantity, &field("resource"))?;
    }
    Ok(reserved)
}

fn signal(value: i32, field: &str) -> Result<EvictionSignal, InvalidMessage> {
    enum_value::<kubelet::EvictionSignal, EvictionSignal>(value, field)
}

fn threshold(
    message: Option<kubelet::Threshold>,
    field: &str,
) -> Result<Threshold, InvalidMessage> {
    Threshold::try_from(invalid_message::required(message, field)?).within(field)
}

fn hard_evictions(
    messages: Vec<kubelet::HardEviction>,
) -> Result<BTreeMap<EvictionSignal, Threshold>, InvalidMessage> {
    let mut evictions = BTreeMap::new();
    for (index, message) in messages.into_iter().enumerate() {
        let field = |name: &str| format!("eviction_hard[{index}].{name}");
        let signal = signal(message.signal, &field("signal"))?;
        let threshold = threshold(message.threshold, &field("threshold"))?;
        insert_once(&mut evictions, signal, threshold, &field("signal"))?;
    }
    Ok(evictions)
}

fn soft_evictions(
    messages: Vec<kubelet::SoftEviction>,
) -> Result<BTreeMap<EvictionSignal, SoftEviction>, InvalidMessage> {
    let mut evictions = BTreeMap::new();
    for (index, message) in messages.into_iter().enumerate() {
        let field = |name: &str| format!("eviction_soft[{index}].{name}");
        let signal = signal(message.signal, &field("signal"))?;
        let threshold = threshold(message.threshold, &field("threshold"))?;
        let grace_period = invalid_message::required(message.grace_period, &field("grace_period"))?;
        let grace_period = Duration::try_from(grace_period).field(&field("grace_period"))?;
        let soft = SoftEviction {
            threshold,
            grace_period,
        };
        insert_once(&mut evictions, signal, soft, &field("signal"))?;
    }
    Ok(evictions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::full_toml;

    fn full_config() -> KubeletConfig {
        toml::from_str(&full_toml()).unwrap()
    }

    #[test]
    fn round_trips_with_the_bootstrap_token() {
        let config = full_config();
        let message = kubelet::Kubelet::from(config.clone());
        assert_eq!(message.bootstrap_token, "abcdef.0123456789abcdef");
        assert_eq!(message.node_taints.len(), 3, "flattened");
        assert_eq!(message.eviction_soft.len(), 2);
        assert!(
            message
                .eviction_soft
                .iter()
                .all(|soft| soft.grace_period.is_some())
        );
        assert_eq!(
            message.eviction_max_pod_grace_period,
            Some(prost_types::Duration {
                seconds: 30,
                nanos: 0
            })
        );
        let thresholds: Vec<_> = message
            .eviction_hard
            .iter()
            .map(|hard| hard.threshold.clone().unwrap().threshold.unwrap())
            .collect();
        assert_eq!(
            thresholds,
            [
                threshold::Threshold::Quantity("100Mi".to_owned()),
                threshold::Threshold::Percent(10.0)
            ]
        );
        assert_eq!(KubeletConfig::try_from(message).unwrap(), config);
    }

    #[test]
    fn defaults_the_cluster_domain() {
        let message = kubelet::Kubelet {
            cluster_domain: String::new(),
            ..full_config().into()
        };
        let config = KubeletConfig::try_from(message).unwrap();
        assert_eq!(config.cluster_domain.as_str(), "cluster.local");
    }

    /// Makes a valid message invalid.
    type Corruption = fn(&mut kubelet::Kubelet);

    #[test]
    fn rejects_what_user_data_rejects() {
        fn image_gc(message: &mut kubelet::Kubelet) -> &mut kubelet::ImageGc {
            message.image_gc.as_mut().unwrap()
        }
        fn threshold(value: threshold::Threshold) -> Option<kubelet::Threshold> {
            Some(kubelet::Threshold {
                threshold: Some(value),
            })
        }
        let valid = kubelet::Kubelet::from(full_config());
        let cases: [(Corruption, &str, &str); 26] = [
            (
                |m| m.bootstrap_token.clear(),
                "bootstrap_token",
                "the empty token of GetSettings",
            ),
            (
                |m| m.api_server = "http://k8s.example.com".to_owned(),
                "api_server",
                "a plain HTTP API server",
            ),
            (
                |m| {
                    m.node_labels
                        .insert("node-role.kubernetes.io/worker".to_owned(), String::new());
                },
                "node_labels",
                "a label kubelet may not set",
            ),
            (
                |m| {
                    m.node_labels.insert("a b".to_owned(), String::new());
                },
                "node_labels",
                "a malformed label key",
            ),
            (
                |m| m.node_taints[1].effect = 0,
                "node_taints[1].effect",
                "a taint without effect",
            ),
            (|m| m.max_pods = Some(0), "max_pods", "no pods"),
            (|m| m.max_pods = Some(70_000), "max_pods", "too many pods"),
            (
                |m| m.cloud_provider = 5,
                "cloud_provider",
                "an unknown cloud provider",
            ),
            (
                |m| m.static_pods[1].name = m.static_pods[0].name.clone(),
                "static_pods[1].name",
                "a static pod given twice",
            ),
            (
                |m| m.static_pods[0].manifest = "kind: Deployment\n".to_owned(),
                "static_pods[0].manifest",
                "a manifest that is not a pod",
            ),
            (
                |m| m.kube_reserved[1].resource = m.kube_reserved[0].resource,
                "kube_reserved[1].resource",
                "a reservation given twice",
            ),
            (
                |m| m.system_reserved[0].quantity = "-1".to_owned(),
                "system_reserved[0].quantity",
                "a negative quantity",
            ),
            (
                |m| m.eviction_hard[0].signal = 0,
                "eviction_hard[0].signal",
                "an unspecified signal",
            ),
            (
                |m| m.eviction_hard[0].threshold = None,
                "eviction_hard[0].threshold",
                "a missing threshold",
            ),
            (
                |m| {
                    m.eviction_hard[1].threshold = threshold(threshold::Threshold::Percent(100.0));
                },
                "eviction_hard[1].threshold.percent",
                "a threshold of 100%",
            ),
            (
                |m| {
                    m.eviction_hard[1].threshold =
                        threshold(threshold::Threshold::Percent(f64::NAN));
                },
                "eviction_hard[1].threshold.percent",
                "a NaN threshold",
            ),
            (
                |m| {
                    m.eviction_hard[0].threshold =
                        threshold(threshold::Threshold::Quantity("10%".to_owned()));
                },
                "eviction_hard[0].threshold.quantity",
                "a percentage as a quantity",
            ),
            (
                |m| m.eviction_soft[0].grace_period = None,
                "eviction_soft[0].grace_period",
                "a soft threshold without grace period",
            ),
            (
                |m| {
                    m.eviction_soft[0].grace_period = Some(prost_types::Duration {
                        seconds: 1,
                        nanos: 1,
                    });
                },
                "eviction_soft[0].grace_period",
                "a sub-millisecond grace period",
            ),
            (
                |m| {
                    m.eviction_max_pod_grace_period = Some(prost_types::Duration {
                        seconds: 1,
                        nanos: 500_000_000,
                    });
                },
                "eviction_max_pod_grace_period",
                "a fractional grace period",
            ),
            (
                |m| {
                    m.eviction_max_pod_grace_period = Some(prost_types::Duration {
                        seconds: i64::from(i32::MAX) + 1,
                        nanos: 0,
                    });
                },
                "eviction_max_pod_grace_period",
                "a grace period beyond kubelet's i32",
            ),
            (
                |m| m.eviction_soft[1].signal = m.eviction_soft[0].signal,
                "eviction_soft[1].signal",
                "a soft threshold given twice",
            ),
            (
                |m| {
                    let thresholds = image_gc(m).threshold_percent.as_mut().unwrap();
                    thresholds.low = thresholds.high;
                },
                "image_gc.threshold_percent",
                "a low image GC threshold at the high one",
            ),
            (
                |m| image_gc(m).threshold_percent.as_mut().unwrap().high = 101,
                "image_gc.threshold_percent.high",
                "a percentage above 100",
            ),
            (
                |m| {
                    image_gc(m).age.as_mut().unwrap().maximum = Some(prost_types::Duration {
                        seconds: 60,
                        nanos: 0,
                    });
                },
                "image_gc.age",
                "a maximum image age below the minimum",
            ),
            (
                |m| image_gc(m).age.as_mut().unwrap().minimum = None,
                "image_gc.age.minimum",
                "image ages without a minimum",
            ),
        ];
        for (corrupt, field, why) in cases {
            let mut message = valid.clone();
            corrupt(&mut message);
            let error = KubeletConfig::try_from(message).expect_err(why);
            assert_eq!(error.field(), field, "{why}: {error}");
        }
    }
}

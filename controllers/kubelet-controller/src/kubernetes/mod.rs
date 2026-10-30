//! `[settings.kubernetes]`: the kubelet of images that ship it, with Bottlerocket's keys and
//! value formats.

mod api_server_url;
mod bootstrap_token;
mod image_gc;
mod kubelet_config;
mod labels;
mod pod_grace_period;
mod resources;
mod soft_eviction;
mod static_pod;
mod taint_value;

pub use api_server_url::ApiServerUrl;
pub use bootstrap_token::BootstrapToken;
pub use image_gc::{ImageAges, ImageGc, Percent, ThresholdPercents};
pub(crate) use kubelet_config::default_cluster_domain;
pub use kubelet_config::{CloudProvider, KubeletConfig};
pub use labels::{LabelValue, NodeLabelKey, QualifiedName};
pub use pod_grace_period::PodGracePeriod;
pub use resources::{Duration, EvictionSignal, Quantity, ReservedResource, Threshold};
pub use soft_eviction::SoftEviction;
pub use static_pod::{PodManifest, StaticPod};
pub use taint_value::{TaintEffect, TaintValue};

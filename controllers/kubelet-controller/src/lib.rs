//! kubelet-controller's API (`hardened.kubelet.v1`, on [`SOCKET`]): kubelet's configuration,
//! `settings.kubernetes` ([`KubeletConfig`]).
//!
//! Everything kubelet would reject at startup (a node label in a namespace it may not set, a
//! malformed taint, a low image GC threshold above the high one) is rejected when the settings
//! are parsed instead, so a typo shows in the user-data error rather than in a crash-looping
//! kubelet.

#![warn(missing_docs)]

mod conversion;
mod kubernetes;
mod socket;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use generated::hardened::kubelet::v1 as kubelet;
pub use kubernetes::{
    ApiServerUrl, BootstrapToken, CloudProvider, Duration, EvictionSignal, ImageAges, ImageGc,
    KubeletConfig, LabelValue, NodeLabelKey, Percent, PodGracePeriod, PodManifest, QualifiedName,
    Quantity, ReservedResource, SoftEviction, StaticPod, TaintEffect, TaintValue, Threshold,
    ThresholdPercents,
};
pub use socket::SOCKET;

//! Kubernetes Container Runtime Interface (`runtime.v1`) client bindings.
//!
//! Generated at build time from `proto/runtime/v1/api.proto`, copied verbatim from the
//! `k8s.io/cri-api` module vendored by the containerd release shipped in the image (see
//! `components/containerd`), so the API matches the runtime exactly.

#![allow(clippy::all, missing_docs)]

include!(concat!(env!("OUT_DIR"), "/cri.rs"));

pub use runtime::v1;

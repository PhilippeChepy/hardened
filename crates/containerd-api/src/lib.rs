//! containerd gRPC API bindings, limited to importing the bundled images (everything else goes
//! through CRI): the streaming, transfer and snapshots services and the types they use.
//!
//! Generated at build time from the protos vendored in `proto/`, copied verbatim from the
//! containerd release shipped in the image (see `components/containerd`). Only the files the
//! import needs are kept; add one (with its imports) when a new call needs it.

#![allow(clippy::all, missing_docs)]

include!(concat!(env!("OUT_DIR"), "/containerd.rs"));

pub use prost_types::Any;

/// Namespace header understood by containerd.
pub const NAMESPACE_HEADER: &str = "containerd-namespace";

/// Packs a message into a `google.protobuf.Any` using containerd's type URL convention
/// (the bare fully-qualified message name).
pub fn to_any<M: prost::Name>(message: &M) -> Any {
    Any {
        type_url: M::full_name(),
        value: prost::Message::encode_to_vec(message),
    }
}

/// Wraps `message` in a request scoped to the given containerd namespace.
pub fn request<T>(namespace: &str, message: T) -> tonic::Request<T> {
    let mut request = tonic::Request::new(message);
    request.metadata_mut().insert(
        NAMESPACE_HEADER,
        namespace.parse().expect("namespace must be a valid header value"),
    );
    request
}

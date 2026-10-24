//! dust-api: the remote front of the dust API.
//!
//! Terminates mutual TLS, maps the client certificate's Organization to a [`Role`](dust_proto::Role),
//! authorizes every call by its gRPC path and forwards permitted calls verbatim (streaming bodies
//! and trailers included) to dust-init's control socket. It knows nothing about individual RPCs.

mod access_log;
pub mod authz;
mod proxy;
pub mod tls;

pub use proxy::serve;

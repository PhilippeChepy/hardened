//! The validated values several controllers share, and what their settings and protobuf
//! conversions are built with.
//!
//! Each type can only hold a valid value: it is checked once, when parsed (from user-data, an
//! API, metadata or DHCP), so code receiving one never re-validates it. Most deserialize from and
//! serialize to their string form. A value only one controller uses is that controller's.
//!
//! [`atomic_file`] is how the services replace the files they write. [`channel()`] and
//! [`lazy_channel`] connect to a service's gRPC API on its unix socket, and [`Forwarder`] relays
//! calls to it.
//!
//! A controller converts the message it receives back into its domain types with `TryFrom`,
//! which validates it as user-data parsing does, failing with an [`InvalidMessage`].

#![warn(missing_docs)]

mod argument;
pub mod atomic_file;
pub mod base64_text;
mod certificates;
mod channel;
mod domain_name;
mod forwarder;
mod hostname;
pub mod invalid_message;
mod invalid_value;
mod non_empty;
mod private_key;
#[cfg(any(test, feature = "testing"))]
pub mod testing;
mod validated_string;
mod workload_name;

pub use argument::Argument;
pub use certificates::Certificates;
pub use channel::channel;
pub use channel::lazy_channel;
pub use domain_name::DomainName;
pub use forwarder::Forwarder;
pub use hostname::Hostname;
pub use invalid_message::InvalidMessage;
pub use invalid_value::InvalidValue;
pub use non_empty::NonEmpty;
pub use private_key::PrivateKey;
pub use workload_name::WorkloadName;

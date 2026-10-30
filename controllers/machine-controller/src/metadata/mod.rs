//! The platform the instance runs on, and the instance metadata and user-data it provides.

mod exoscale;
mod http;
mod platform;
mod qemu;

pub use platform::Metadata;
pub use platform::Platform;

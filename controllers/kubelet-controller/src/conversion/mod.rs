//! Conversions between `settings.kubernetes` and kubelet-controller's messages.
//!
//! `From` a domain value to its message is lossless, the bootstrap token included. `TryFrom` a
//! message validates it as user-data parsing does, and fails with an
//! [`InvalidMessage`](controllers_helpers::InvalidMessage) naming the field at fault.

mod duration;
mod kubelet;

//! The nftables ruleset a configuration comes to: the table `inet firewall-controller`, its base
//! chains and their rules, as typed values. [`text`] writes it in nft's syntax (what `nft list
//! table inet firewall-controller` shows); `crate::nftables` sends it to the kernel.

mod icmp_type;
mod rule;
#[allow(
    clippy::module_inception,
    reason = "the module of `Ruleset`, the root of the others"
)]
mod ruleset;
pub mod text;

pub use icmp_type::{IcmpType, Icmpv6Type};
pub use rule::{Action, Chain, ChainPolicy, CtStates, Hook, Match, Rule};
pub use ruleset::{FAMILY, LOG_PREFIX_IN, LOG_PREFIX_OUT, LOG_RATE, Ruleset, TABLE};

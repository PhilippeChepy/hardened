//! nf_tables' netlink API (`NETLINK_NETFILTER`, `NFNL_SUBSYS_NFTABLES`), the part the
//! controller speaks: a [`Ruleset`](crate::Ruleset) encoded as one batch (a transaction: the
//! table replaced atomically), and the table's rules read back with their counters. Linux's ABI
//! (`include/uapi/linux/netfilter/nf_tables.h`); what nft itself sends for the same rules, so that
//! `nft list` shows them as [`crate::ruleset::text`] writes them.

pub mod attr;
mod expr;
mod messages;
#[cfg(test)]
mod netns;
mod nfta;
mod requests;
mod rule_info;
pub mod socket;

pub use expr::AnonymousSet;
pub use messages::{BATCH_BEGIN, BATCH_END, FAMILY_INET, MessageKind, Messages, SUBSYSTEM, flags};
pub use requests::{batch, get_generation, get_rules, get_table};
pub use rule_info::{RuleInfo, parse_generation};

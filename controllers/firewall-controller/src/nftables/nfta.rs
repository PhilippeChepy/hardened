//! nf_tables' attribute numbers (`NFTA_*`), and nftnl's rule user data.

pub(crate) const TABLE_NAME: u16 = 1;
pub(crate) const TABLE_FLAGS: u16 = 2;

pub(crate) const CHAIN_TABLE: u16 = 1;
pub(crate) const CHAIN_NAME: u16 = 3;
pub(crate) const CHAIN_HOOK: u16 = 4;
pub(crate) const CHAIN_POLICY: u16 = 5;
pub(crate) const CHAIN_TYPE: u16 = 7;
pub(crate) const HOOK_HOOKNUM: u16 = 1;
pub(crate) const HOOK_PRIORITY: u16 = 2;

pub(crate) const RULE_TABLE: u16 = 1;
pub(crate) const RULE_CHAIN: u16 = 2;
pub(crate) const RULE_HANDLE: u16 = 3;
pub(crate) const RULE_EXPRESSIONS: u16 = 4;
pub(crate) const RULE_USERDATA: u16 = 7;

pub(crate) const LIST_ELEM: u16 = 1;
pub(crate) const EXPR_NAME: u16 = 1;
pub(crate) const EXPR_DATA: u16 = 2;

pub(crate) const COUNTER_BYTES: u16 = 1;
pub(crate) const COUNTER_PACKETS: u16 = 2;

pub(crate) const GEN_ID: u16 = 1;

/// nftnl's rule user data: a TLV of a byte of type, a byte of length; `NFTNL_UDATA_RULE_COMMENT`.
pub(crate) const UDATA_RULE_COMMENT: u8 = 0;

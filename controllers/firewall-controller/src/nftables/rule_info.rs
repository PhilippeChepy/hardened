//! What the kernel answers: the table's rules, and the generation.

use super::attr;
use super::attr::Attrs;
use super::nfta;
use crate::ruleset::Hook;
use crate::ruleset::TABLE;

/// The comment of nftnl's rule user data, if any.
fn udata_comment(mut udata: &[u8]) -> Option<String> {
    while let [kind, len, rest @ ..] = udata {
        let value = rest.get(..usize::from(*len))?;
        if *kind == nfta::UDATA_RULE_COMMENT {
            let text = value.strip_suffix(&[0]).unwrap_or(value);
            return Some(String::from_utf8_lossy(text).into_owned());
        }
        udata = &rest[usize::from(*len)..];
    }
    None
}

/// A rule of the table, as the kernel has it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleInfo {
    /// Its chain's name.
    pub chain: String,
    /// Its handle.
    pub handle: u64,
    /// Its comment, empty without one.
    pub comment: String,
    /// Its counter's packets and bytes, 0 without one.
    pub packets: u64,
    /// Bytes.
    pub bytes: u64,
}

impl RuleInfo {
    /// The rule a NEWRULE's attributes describe; `None` when not one of the table's.
    #[must_use]
    pub fn parse(attrs: Attrs<'_>) -> Option<Self> {
        let table = attrs.find(nfta::RULE_TABLE)?.string()?;
        if table != TABLE {
            return None;
        }
        let chain = attrs.find(nfta::RULE_CHAIN)?.string()?.to_owned();
        let handle = attrs.find(nfta::RULE_HANDLE).and_then(attr::Attr::be64)?;
        let comment = (attrs.find(nfta::RULE_USERDATA))
            .and_then(|udata| udata_comment(udata.value))
            .unwrap_or_default();
        let counter = (attrs.find(nfta::RULE_EXPRESSIONS))
            .into_iter()
            .flat_map(|list| list.nested())
            .map(attr::Attr::nested)
            .find(|expression| {
                expression
                    .find(nfta::EXPR_NAME)
                    .and_then(attr::Attr::string)
                    == Some("counter")
            })
            .and_then(|expression| expression.find(nfta::EXPR_DATA))
            .map(attr::Attr::nested);
        let count = |kind| {
            counter
                .and_then(|c| c.find(kind))
                .and_then(attr::Attr::be64)
        };
        Some(Self {
            chain,
            handle,
            comment,
            packets: count(nfta::COUNTER_PACKETS).unwrap_or(0),
            bytes: count(nfta::COUNTER_BYTES).unwrap_or(0),
        })
    }

    /// The hook of its chain, if one of ours.
    #[must_use]
    pub fn hook(&self) -> Option<Hook> {
        [Hook::Input, Hook::Output]
            .into_iter()
            .find(|hook| hook.name() == self.chain)
    }
}

/// The generation a NEWGEN's attributes give.
#[must_use]
pub fn parse_generation(attrs: Attrs<'_>) -> Option<u32> {
    attrs.find(nfta::GEN_ID).and_then(attr::Attr::be32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables::requests::comment_udata;

    #[test]
    fn comments_round_trip() {
        for comment in ["ssh", "6000-6010/udp", ""] {
            assert_eq!(
                udata_comment(&comment_udata(comment)).as_deref(),
                Some(comment)
            );
        }
        assert_eq!(comment_udata("ssh"), b"\x00\x04ssh\x00");
        // Another TLV first; a truncated one.
        assert_eq!(
            udata_comment(b"\x01\x01x\x00\x02a\x00").as_deref(),
            Some("a")
        );
        assert_eq!(udata_comment(b"\x00\x09ab"), None);
    }
}

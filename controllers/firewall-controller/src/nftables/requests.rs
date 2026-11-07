//! The requests: the batch replacing the table, and the reads of the table, its rules and the
//! generation.

use super::BATCH_BEGIN;
use super::BATCH_END;
use super::MessageKind;
use super::Messages;
use super::SUBSYSTEM;
use super::attr::Writer;
use super::expr;
use super::flags;
use super::nfta;
use crate::ruleset::Ruleset;
use crate::ruleset::TABLE;

/// The batch replacing the table by `ruleset`, or removing it (`None`): created if it does not
/// exist, deleted, then created again with its chains, sets and rules, in one transaction. Every
/// message is acknowledged.
#[must_use]
pub fn batch(ruleset: Option<&Ruleset>, first_sequence: u32) -> Messages {
    use flags::{ACK, APPEND, CREATE, REQUEST};
    let mut messages = Messages::new(first_sequence);
    messages.push(BATCH_BEGIN, REQUEST, 0, SUBSYSTEM, &[]);
    let table = table_attrs();
    messages.nftables(MessageKind::NewTable, REQUEST | ACK | CREATE, &table);
    messages.label(format!("creating the table {TABLE}"));
    let mut name_only = Writer::new();
    name_only.string(nfta::TABLE_NAME, TABLE);
    let name_only = name_only.into_bytes();
    messages.nftables(MessageKind::DelTable, REQUEST | ACK, &name_only);
    messages.label(format!("deleting the table {TABLE}"));
    if let Some(ruleset) = ruleset {
        messages.nftables(MessageKind::NewTable, REQUEST | ACK | CREATE, &table);
        messages.label(format!("creating the table {TABLE}"));
        for chain in &ruleset.chains {
            let mut attrs = Writer::new();
            attrs
                .string(nfta::CHAIN_TABLE, TABLE)
                .string(nfta::CHAIN_NAME, chain.hook.name())
                .nested(nfta::CHAIN_HOOK, |hook| {
                    hook.be32(nfta::HOOK_HOOKNUM, chain.hook.number())
                        .be32(nfta::HOOK_PRIORITY, 0);
                })
                .be32(
                    nfta::CHAIN_POLICY,
                    match chain.policy {
                        crate::ruleset::ChainPolicy::Accept => 1,
                        crate::ruleset::ChainPolicy::Drop => 0,
                    },
                )
                .string(nfta::CHAIN_TYPE, "filter");
            messages.nftables(
                MessageKind::NewChain,
                REQUEST | ACK | CREATE,
                &attrs.into_bytes(),
            );
            messages.label(format!("creating the chain {}", chain.hook.name()));
        }
        let mut set_ids = 0;
        for (hook, rule) in ruleset.rules() {
            let compiled = expr::compile(rule, &mut set_ids);
            for set in &compiled.sets {
                let (set_attrs, elements) = set.attrs();
                messages.nftables(MessageKind::NewSet, REQUEST | ACK | CREATE, &set_attrs);
                messages.label(format!("creating the set of the rule {:?}", rule.comment));
                messages.nftables(MessageKind::NewSetElem, REQUEST | ACK | CREATE, &elements);
                messages.label(format!("filling the set of the rule {:?}", rule.comment));
            }
            let mut attrs = Writer::new();
            attrs
                .string(nfta::RULE_TABLE, TABLE)
                .string(nfta::RULE_CHAIN, hook.name())
                .nested(nfta::RULE_EXPRESSIONS, |list| {
                    for expression in &compiled.expressions {
                        list.nested(nfta::LIST_ELEM, |elem| expression.write(elem));
                    }
                })
                .bytes(nfta::RULE_USERDATA, &comment_udata(&rule.comment));
            messages.nftables(
                MessageKind::NewRule,
                REQUEST | ACK | CREATE | APPEND,
                &attrs.into_bytes(),
            );
            messages.label(format!(
                "adding the rule {:?} to {}: {}",
                rule.comment,
                hook.name(),
                crate::ruleset::text::rule_text(rule)
            ));
        }
    }
    messages.push(BATCH_END, REQUEST, 0, SUBSYSTEM, &[]);
    messages
}

fn table_attrs() -> Vec<u8> {
    let mut attrs = Writer::new();
    attrs
        .string(nfta::TABLE_NAME, TABLE)
        .be32(nfta::TABLE_FLAGS, 0);
    attrs.into_bytes()
}

/// A rule's comment as nftnl's user data. Comments are ours, short: past 127 bytes, cut.
pub(crate) fn comment_udata(comment: &str) -> Vec<u8> {
    let mut text = comment.as_bytes().to_vec();
    text.truncate(127);
    text.push(0);
    let mut udata = vec![
        nfta::UDATA_RULE_COMMENT,
        u8::try_from(text.len()).unwrap_or(128),
    ];
    udata.extend_from_slice(&text);
    udata
}

/// The request of the table's existence: a NEWTABLE answers it, or ENOENT.
#[must_use]
pub fn get_table(sequence: u32) -> Messages {
    let mut messages = Messages::new(sequence);
    let mut attrs = Writer::new();
    attrs.string(nfta::TABLE_NAME, TABLE);
    messages.nftables(MessageKind::GetTable, flags::REQUEST, &attrs.into_bytes());
    messages
}

/// The request of the table's rules (a dump of NEWRULE).
#[must_use]
pub fn get_rules(sequence: u32) -> Messages {
    let mut messages = Messages::new(sequence);
    let mut attrs = Writer::new();
    attrs.string(nfta::RULE_TABLE, TABLE);
    messages.nftables(
        MessageKind::GetRule,
        flags::REQUEST | flags::DUMP,
        &attrs.into_bytes(),
    );
    messages
}

/// The request of the generation: a NEWGEN answers it.
#[must_use]
pub fn get_generation(sequence: u32) -> Messages {
    let mut messages = Messages::new(sequence);
    messages.push(
        MessageKind::GetGen.netlink_type(),
        flags::REQUEST,
        0,
        0,
        &[],
    );
    messages
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nftables::RuleInfo;
    use crate::nftables::attr::Attrs;
    use crate::policy::FirewallConfig;
    use crate::ruleset::Hook;
    /// The messages of `datagram`: their types, flags and attributes.
    fn split(mut datagram: &[u8]) -> Vec<(u16, u16, Vec<u8>)> {
        let mut messages = Vec::new();
        while let Some(header) = datagram.first_chunk::<16>() {
            let len = u32::from_ne_bytes(header[..4].try_into().unwrap()) as usize;
            let kind = u16::from_ne_bytes([header[4], header[5]]);
            let flags = u16::from_ne_bytes([header[6], header[7]]);
            messages.push((kind, flags, datagram[20..len].to_vec()));
            datagram = &datagram[len..];
        }
        messages
    }

    #[test]
    fn a_batch_replaces_the_table() {
        let config = FirewallConfig {
            enabled: true,
            ..FirewallConfig::default()
        };
        let ruleset = Ruleset::of(&config).unwrap();
        let messages = batch(Some(&ruleset), 100);
        let split = split(messages.bytes());
        let kinds: Vec<_> = split.iter().map(|(kind, _, _)| *kind).collect();
        let nft = |kind: MessageKind| kind.netlink_type();
        let rules = ruleset.rules().count();
        assert_eq!(
            kinds[..5],
            [
                BATCH_BEGIN,
                nft(MessageKind::NewTable),
                nft(MessageKind::DelTable),
                nft(MessageKind::NewTable),
                nft(MessageKind::NewChain)
            ]
        );
        assert_eq!(*kinds.last().unwrap(), BATCH_END);
        // The icmp and icmpv6 rules' sets, each with its elements.
        assert_eq!(
            kinds
                .iter()
                .filter(|&&k| k == nft(MessageKind::NewSet))
                .count(),
            2
        );
        assert_eq!(
            kinds
                .iter()
                .filter(|&&k| k == nft(MessageKind::NewRule))
                .count(),
            rules
        );
        assert_eq!(messages.sequences().len(), split.len());
        assert_eq!(messages.sequences()[0], 100);
        assert_eq!(messages.next_sequence(), 100 + split.len() as u32);
        for (kind, flags, _) in &split[1..split.len() - 1] {
            assert_ne!(flags & flags::ACK, 0, "{kind:#x} is acknowledged");
        }
        // The rules read back as the kernel echoes them (same attributes, plus a handle).
        let (_, _, rule) = split
            .iter()
            .find(|(kind, _, _)| *kind == nft(MessageKind::NewRule))
            .unwrap();
        let mut with_handle = rule.clone();
        let mut handle = Writer::new();
        handle.be64(nfta::RULE_HANDLE, 4);
        with_handle.extend(handle.into_bytes());
        let info = RuleInfo::parse(Attrs(&with_handle)).unwrap();
        assert_eq!(info.chain, "input");
        assert_eq!(info.comment, "loopback");
        assert_eq!(info.hook(), Some(Hook::Input));
        assert_eq!((info.handle, info.packets), (4, 0));
    }

    #[test]
    fn disabling_removes_the_table() {
        let messages = batch(None, 1);
        let kinds: Vec<_> = split(messages.bytes()).iter().map(|(k, _, _)| *k).collect();
        assert_eq!(
            kinds,
            [
                BATCH_BEGIN,
                MessageKind::NewTable.netlink_type(),
                MessageKind::DelTable.netlink_type(),
                BATCH_END
            ]
        );
    }
}

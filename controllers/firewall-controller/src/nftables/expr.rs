//! A [`Rule`] as nf_tables expressions, the registers' way: loads into register 1, compared,
//! then the verdict. The same expressions nft generates for the rule's text.

use super::attr::Writer;
use super::nfta;
use crate::ports::Ports;
use crate::ports::Protocol;
use crate::ruleset::Action;
use crate::ruleset::LOG_RATE;
use crate::ruleset::Match;
use crate::ruleset::Rule;
use crate::ruleset::TABLE;

/// `NFT_REG_VERDICT` and `NFT_REG_1`.
const REG_VERDICT: u32 = 0;
const REG_1: u32 = 1;
/// `IFNAMSIZ`: interface names compare on 16 bytes, NUL-padded.
const IFNAMSIZ: usize = 16;

/// `NFT_META_*`.
const META_IIFNAME: u32 = 6;
const META_OIFNAME: u32 = 7;
const META_NFPROTO: u32 = 15;
const META_L4PROTO: u32 = 16;
/// `NFPROTO_IPV4`, `NFPROTO_IPV6`; the ICMP protocols' numbers.
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const IPPROTO_ICMP: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;
/// `NFT_CT_STATE`.
const CT_STATE: u32 = 0;
/// `NFT_PAYLOAD_TRANSPORT_HEADER`.
const TRANSPORT_HEADER: u32 = 2;
/// `NFT_CMP_EQ`, `NFT_CMP_NEQ`, `NFT_RANGE_EQ`.
const CMP_EQ: u32 = 0;
const CMP_NEQ: u32 = 1;
const RANGE_EQ: u32 = 0;
/// `NF_DROP`, `NF_ACCEPT`.
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
/// `NFT_REJECT_TCP_RST`, `NFT_REJECT_ICMPX_UNREACH` and `NFT_REJECT_ICMPX_PORT_UNREACH`.
const REJECT_TCP_RST: u32 = 1;
const REJECT_ICMPX_UNREACH: u32 = 2;
const ICMPX_PORT_UNREACH: u8 = 1;
/// syslog's `LOG_INFO`.
const LOG_LEVEL_INFO: u32 = 6;
/// nft's data types of the sets' keys: `TYPE_ICMP_TYPE`, `TYPE_ICMP6_TYPE`.
const TYPE_ICMP_TYPE: u32 = 14;
const TYPE_ICMP6_TYPE: u32 = 29;
/// `NFT_SET_ANONYMOUS | NFT_SET_CONSTANT`.
const SET_ANONYMOUS_CONSTANT: u32 = 0x1 | 0x2;
/// The name of an anonymous set, which the kernel numbers.
const ANONYMOUS_SET_NAME: &str = "__set%d";

/// An expression, with its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expression {
    /// `meta load KEY => reg 1`.
    Meta(u32),
    /// `cmp OP reg 1 DATA`.
    Cmp(u32, Vec<u8>),
    /// `bitwise reg 1 = (reg 1 & MASK) ^ 0`.
    Bitwise(Vec<u8>),
    /// `ct load KEY => reg 1`.
    Ct(u32),
    /// `payload load LEN @ transport header + OFFSET => reg 1`.
    Payload { offset: u32, len: u32 },
    /// `range eq reg 1 FROM TO`.
    Range(Vec<u8>, Vec<u8>),
    /// `lookup reg 1 set` of the batch's set `id`.
    Lookup(u32),
    /// `counter`.
    Counter,
    /// `limit rate N/second burst B type packets`.
    Limit,
    /// `log prefix P level info`.
    Log(&'static str),
    /// `reject type T code C`.
    Reject(u32, u8),
    /// `immediate reg 0 VERDICT`.
    Verdict(u32),
}

/// nf_tables' expression attributes.
mod attrs {
    pub const META_DREG: u16 = 1;
    pub const META_KEY: u16 = 2;
    pub const CMP_SREG: u16 = 1;
    pub const CMP_OP: u16 = 2;
    pub const CMP_DATA: u16 = 3;
    pub const BITWISE_SREG: u16 = 1;
    pub const BITWISE_DREG: u16 = 2;
    pub const BITWISE_LEN: u16 = 3;
    pub const BITWISE_MASK: u16 = 4;
    pub const BITWISE_XOR: u16 = 5;
    pub const CT_DREG: u16 = 1;
    pub const CT_KEY: u16 = 2;
    pub const PAYLOAD_DREG: u16 = 1;
    pub const PAYLOAD_BASE: u16 = 2;
    pub const PAYLOAD_OFFSET: u16 = 3;
    pub const PAYLOAD_LEN: u16 = 4;
    pub const RANGE_SREG: u16 = 1;
    pub const RANGE_OP: u16 = 2;
    pub const RANGE_FROM: u16 = 3;
    pub const RANGE_TO: u16 = 4;
    pub const LOOKUP_SET: u16 = 1;
    pub const LOOKUP_SREG: u16 = 2;
    pub const LOOKUP_SET_ID: u16 = 4;
    pub const LIMIT_RATE: u16 = 1;
    pub const LIMIT_UNIT: u16 = 2;
    pub const LIMIT_BURST: u16 = 3;
    pub const LIMIT_TYPE: u16 = 4;
    pub const LIMIT_FLAGS: u16 = 5;
    pub const LOG_PREFIX: u16 = 2;
    pub const LOG_LEVEL: u16 = 5;
    pub const REJECT_TYPE: u16 = 1;
    pub const REJECT_ICMP_CODE: u16 = 2;
    pub const IMMEDIATE_DREG: u16 = 1;
    pub const IMMEDIATE_DATA: u16 = 2;
    pub const DATA_VALUE: u16 = 1;
    pub const DATA_VERDICT: u16 = 2;
    pub const VERDICT_CODE: u16 = 1;

    pub const SET_TABLE: u16 = 1;
    pub const SET_NAME: u16 = 2;
    pub const SET_FLAGS: u16 = 3;
    pub const SET_KEY_TYPE: u16 = 4;
    pub const SET_KEY_LEN: u16 = 5;
    pub const SET_ID: u16 = 10;
    pub const SET_USERDATA: u16 = 13;
    pub const SET_ELEM_LIST_TABLE: u16 = 1;
    pub const SET_ELEM_LIST_SET: u16 = 2;
    pub const SET_ELEM_LIST_ELEMENTS: u16 = 3;
    pub const SET_ELEM_LIST_SET_ID: u16 = 4;
    pub const SET_ELEM_KEY: u16 = 1;
}

impl Expression {
    /// nf_tables' name for it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Meta(_) => "meta",
            Self::Cmp(..) => "cmp",
            Self::Bitwise(_) => "bitwise",
            Self::Ct(_) => "ct",
            Self::Payload { .. } => "payload",
            Self::Range(..) => "range",
            Self::Lookup(_) => "lookup",
            Self::Counter => "counter",
            Self::Limit => "limit",
            Self::Log(_) => "log",
            Self::Reject(..) => "reject",
            Self::Verdict(_) => "immediate",
        }
    }

    /// Writes it as a list element's attributes: its name and data.
    pub fn write(&self, elem: &mut Writer) {
        use attrs::*;
        let value = |writer: &mut Writer, kind, bytes: &[u8]| {
            writer.nested(kind, |data| {
                data.bytes(DATA_VALUE, bytes);
            });
        };
        elem.string(nfta::EXPR_NAME, self.name());
        elem.nested(nfta::EXPR_DATA, |data| match self {
            Self::Meta(key) => {
                data.be32(META_KEY, *key).be32(META_DREG, REG_1);
            }
            Self::Cmp(op, bytes) => {
                data.be32(CMP_SREG, REG_1).be32(CMP_OP, *op);
                value(data, CMP_DATA, bytes);
            }
            Self::Bitwise(mask) => {
                let len = u32::try_from(mask.len()).unwrap_or(u32::MAX);
                data.be32(BITWISE_SREG, REG_1)
                    .be32(BITWISE_DREG, REG_1)
                    .be32(BITWISE_LEN, len);
                value(data, BITWISE_MASK, mask);
                value(data, BITWISE_XOR, &vec![0; mask.len()]);
            }
            Self::Ct(key) => {
                data.be32(CT_KEY, *key).be32(CT_DREG, REG_1);
            }
            Self::Payload { offset, len } => {
                data.be32(PAYLOAD_DREG, REG_1)
                    .be32(PAYLOAD_BASE, TRANSPORT_HEADER)
                    .be32(PAYLOAD_OFFSET, *offset)
                    .be32(PAYLOAD_LEN, *len);
            }
            Self::Range(from, to) => {
                data.be32(RANGE_SREG, REG_1).be32(RANGE_OP, RANGE_EQ);
                value(data, RANGE_FROM, from);
                value(data, RANGE_TO, to);
            }
            Self::Lookup(id) => {
                data.string(LOOKUP_SET, ANONYMOUS_SET_NAME)
                    .be32(LOOKUP_SREG, REG_1)
                    .be32(LOOKUP_SET_ID, *id);
            }
            Self::Counter => {}
            Self::Limit => {
                data.be64(LIMIT_RATE, LOG_RATE.0)
                    // Per second.
                    .be64(LIMIT_UNIT, 1)
                    .be32(LIMIT_BURST, LOG_RATE.1)
                    // NFT_LIMIT_PKTS.
                    .be32(LIMIT_TYPE, 0)
                    .be32(LIMIT_FLAGS, 0);
            }
            Self::Log(prefix) => {
                data.string(LOG_PREFIX, prefix)
                    .be32(LOG_LEVEL, LOG_LEVEL_INFO);
            }
            Self::Reject(kind, code) => {
                data.be32(REJECT_TYPE, *kind)
                    .bytes(REJECT_ICMP_CODE, &[*code]);
            }
            Self::Verdict(code) => {
                data.be32(IMMEDIATE_DREG, REG_VERDICT)
                    .nested(IMMEDIATE_DATA, |immediate| {
                        immediate.nested(DATA_VERDICT, |verdict| {
                            verdict.be32(VERDICT_CODE, *code);
                        });
                    });
            }
        });
    }
}

/// An anonymous constant set of one-byte keys (ICMP types), defined in the rule's batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnonymousSet {
    /// Its id in the batch (`NFTA_SET_ID`), from 1.
    pub id: u32,
    /// nft's data type of the keys.
    pub key_type: u32,
    /// The keys.
    pub keys: Vec<u8>,
}

impl AnonymousSet {
    /// The attributes of its NEWSET and NEWSETELEM.
    #[must_use]
    pub fn attrs(&self) -> (Vec<u8>, Vec<u8>) {
        use attrs::*;
        let mut set = Writer::new();
        set.string(SET_TABLE, TABLE)
            .string(SET_NAME, ANONYMOUS_SET_NAME)
            .be32(SET_FLAGS, SET_ANONYMOUS_CONSTANT)
            .be32(SET_KEY_TYPE, self.key_type)
            .be32(SET_KEY_LEN, 1)
            .be32(SET_ID, self.id)
            // nftnl's NFTNL_UDATA_SET_KEYBYTEORDER: big endian (nft's BYTEORDER_BIG_ENDIAN).
            .bytes(SET_USERDATA, &[0, 4, 2, 0, 0, 0]);
        let mut elements = Writer::new();
        elements
            .string(SET_ELEM_LIST_TABLE, TABLE)
            .string(SET_ELEM_LIST_SET, ANONYMOUS_SET_NAME)
            .be32(SET_ELEM_LIST_SET_ID, self.id)
            .nested(SET_ELEM_LIST_ELEMENTS, |list| {
                for key in &self.keys {
                    list.nested(nfta::LIST_ELEM, |elem| {
                        elem.nested(SET_ELEM_KEY, |data| {
                            data.bytes(DATA_VALUE, &[*key]);
                        });
                    });
                }
            });
        (set.into_bytes(), elements.into_bytes())
    }
}

/// A rule's expressions, and the sets they look up.
#[derive(Debug, Default)]
pub struct Compiled {
    /// Defined before the rule.
    pub sets: Vec<AnonymousSet>,
    /// In order.
    pub expressions: Vec<Expression>,
}

impl Compiled {
    fn load_and_compare(&mut self, load: Expression, bytes: Vec<u8>) {
        self.expressions.push(load);
        self.expressions.push(Expression::Cmp(CMP_EQ, bytes));
    }

    /// The ICMP types `keys` of `nfproto` and `protocol`: compared to one, looked up in a set of
    /// several (numbered after `set_ids`).
    fn icmp(&mut self, family: (u8, u8, u32), keys: Vec<u8>, set_ids: &mut u32) {
        let (nfproto, protocol, key_type) = family;
        self.load_and_compare(Expression::Meta(META_NFPROTO), vec![nfproto]);
        self.load_and_compare(Expression::Meta(META_L4PROTO), vec![protocol]);
        let load = Expression::Payload { offset: 0, len: 1 };
        if let [key] = keys[..] {
            self.load_and_compare(load, vec![key]);
        } else {
            *set_ids += 1;
            self.expressions.push(load);
            self.expressions.push(Expression::Lookup(*set_ids));
            self.sets.push(AnonymousSet {
                id: *set_ids,
                key_type,
                keys,
            });
        }
    }

    /// The port at `offset` of the transport header within `ports`.
    fn ports(&mut self, offset: u32, ports: Ports) {
        self.expressions
            .push(Expression::Payload { offset, len: 2 });
        let first = ports.first().get().to_be_bytes().to_vec();
        if ports.first() == ports.last() {
            self.expressions.push(Expression::Cmp(CMP_EQ, first));
        } else {
            let last = ports.last().get().to_be_bytes().to_vec();
            self.expressions.push(Expression::Range(first, last));
        }
    }
}

/// An interface name as `iifname` and `oifname` compare it.
fn interface_name(name: &str) -> Vec<u8> {
    let mut bytes = name.as_bytes().to_vec();
    bytes.resize(IFNAMSIZ, 0);
    bytes
}

/// `rule`'s expressions; its anonymous sets numbered from `set_ids` + 1, which it advances.
#[must_use]
pub fn compile(rule: &Rule, set_ids: &mut u32) -> Compiled {
    let mut compiled = Compiled::default();
    for matched in &rule.matches {
        match matched {
            Match::InterfaceIn(name) => {
                compiled.load_and_compare(Expression::Meta(META_IIFNAME), interface_name(name));
            }
            Match::InterfaceOut(name) => {
                compiled.load_and_compare(Expression::Meta(META_OIFNAME), interface_name(name));
            }
            Match::CtState(states) => {
                compiled.expressions.push(Expression::Ct(CT_STATE));
                // The state's register is in host order.
                compiled
                    .expressions
                    .push(Expression::Bitwise(states.bits().to_ne_bytes().to_vec()));
                compiled
                    .expressions
                    .push(Expression::Cmp(CMP_NEQ, vec![0; 4]));
            }
            Match::Icmp(types) => {
                let keys = types.iter().map(|t| t.number()).collect();
                compiled.icmp((NFPROTO_IPV4, IPPROTO_ICMP, TYPE_ICMP_TYPE), keys, set_ids);
            }
            Match::Icmpv6(types) => {
                let keys = types.iter().map(|t| t.number()).collect();
                compiled.icmp(
                    (NFPROTO_IPV6, IPPROTO_ICMPV6, TYPE_ICMP6_TYPE),
                    keys,
                    set_ids,
                );
            }
            Match::L4Proto(protocol) => {
                compiled.load_and_compare(Expression::Meta(META_L4PROTO), vec![protocol.number()]);
            }
            Match::Ports {
                protocol,
                source,
                destination,
            } => {
                let protocol: &Protocol = protocol;
                compiled.load_and_compare(Expression::Meta(META_L4PROTO), vec![protocol.number()]);
                if let Some(source) = source {
                    compiled.ports(0, *source);
                }
                if let Some(destination) = destination {
                    compiled.ports(2, *destination);
                }
            }
        }
    }
    // The log rule counts what its limit lets through: `limit ... counter log`, as nft does.
    if let Action::Log(prefix) = rule.action {
        compiled.expressions.push(Expression::Limit);
        if rule.counter {
            compiled.expressions.push(Expression::Counter);
        }
        compiled.expressions.push(Expression::Log(prefix));
        return compiled;
    }
    if rule.counter {
        compiled.expressions.push(Expression::Counter);
    }
    match rule.action {
        Action::Accept => compiled.expressions.push(Expression::Verdict(NF_ACCEPT)),
        Action::Drop => compiled.expressions.push(Expression::Verdict(NF_DROP)),
        Action::RejectTcpReset => compiled
            .expressions
            .push(Expression::Reject(REJECT_TCP_RST, 0)),
        Action::RejectPortUnreachable => compiled
            .expressions
            .push(Expression::Reject(REJECT_ICMPX_UNREACH, ICMPX_PORT_UNREACH)),
        Action::Log(_) => {}
    }
    compiled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::CtStates;
    use crate::ruleset::IcmpType;
    use crate::ruleset::Icmpv6Type;

    fn rule(matches: Vec<Match>, counter: bool, action: Action) -> Rule {
        Rule {
            matches,
            counter,
            action,
            comment: String::new(),
        }
    }

    #[test]
    fn compiles_as_nft_does() {
        let mut ids = 0;
        // `ct state established,related counter accept`.
        let compiled = compile(
            &rule(
                vec![Match::CtState(CtStates::ESTABLISHED_RELATED)],
                true,
                Action::Accept,
            ),
            &mut ids,
        );
        assert_eq!(
            compiled.expressions,
            [
                Expression::Ct(CT_STATE),
                Expression::Bitwise(6u32.to_ne_bytes().to_vec()),
                Expression::Cmp(CMP_NEQ, vec![0; 4]),
                Expression::Counter,
                Expression::Verdict(NF_ACCEPT),
            ]
        );
        // `udp dport 6000-6010 drop`.
        let ports = "6000-6010/udp".parse().unwrap();
        let compiled = compile(
            &rule(
                vec![Match::Ports {
                    protocol: Protocol::Udp,
                    source: None,
                    destination: Some(ports),
                }],
                false,
                Action::Drop,
            ),
            &mut ids,
        );
        assert_eq!(
            compiled.expressions,
            [
                Expression::Meta(META_L4PROTO),
                Expression::Cmp(CMP_EQ, vec![17]),
                Expression::Payload { offset: 2, len: 2 },
                Expression::Range(vec![0x17, 0x70], vec![0x17, 0x7a]),
                Expression::Verdict(NF_DROP),
            ]
        );
        assert_eq!(ids, 0);
        // A set of ICMPv6 types, then a single ICMP one.
        let types = vec![Icmpv6Type::NdNeighborSolicit, Icmpv6Type::NdNeighborAdvert];
        let compiled = compile(
            &rule(vec![Match::Icmpv6(types)], false, Action::Accept),
            &mut ids,
        );
        assert_eq!(
            compiled.sets,
            [AnonymousSet {
                id: 1,
                key_type: TYPE_ICMP6_TYPE,
                keys: vec![135, 136]
            }]
        );
        assert_eq!(
            compiled.expressions[4..6],
            [
                Expression::Payload { offset: 0, len: 1 },
                Expression::Lookup(1)
            ]
        );
        let compiled = compile(
            &rule(
                vec![Match::Icmp(vec![IcmpType::EchoRequest])],
                true,
                Action::Accept,
            ),
            &mut ids,
        );
        assert!(compiled.sets.is_empty());
        assert_eq!(
            compiled.expressions[..6],
            [
                Expression::Meta(META_NFPROTO),
                Expression::Cmp(CMP_EQ, vec![NFPROTO_IPV4]),
                Expression::Meta(META_L4PROTO),
                Expression::Cmp(CMP_EQ, vec![IPPROTO_ICMP]),
                Expression::Payload { offset: 0, len: 1 },
                Expression::Cmp(CMP_EQ, vec![8]),
            ]
        );
        // The log rule: rate-limited, counted after the limit, no verdict.
        let compiled = compile(&rule(Vec::new(), true, Action::Log("x: ")), &mut ids);
        assert_eq!(
            compiled.expressions,
            [
                Expression::Limit,
                Expression::Counter,
                Expression::Log("x: ")
            ]
        );
        assert_eq!(interface_name("lo"), b"lo\0\0\0\0\0\0\0\0\0\0\0\0\0\0");
    }
}

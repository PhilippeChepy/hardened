//! A ruleset's chains and rules, as typed values.

use super::IcmpType;
use super::Icmpv6Type;
use crate::ports::Ports;
use crate::ports::Protocol;

/// A base chain of type filter, at priority filter (0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    /// Where it is hooked, which names it.
    pub hook: Hook,
    /// What happens to packets no rule decides on.
    pub policy: ChainPolicy,
    /// In order.
    pub rules: Vec<Rule>,
}

/// A netfilter hook of the inet family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hook {
    /// NF_INET_LOCAL_IN: packets to the machine.
    Input,
    /// NF_INET_LOCAL_OUT: packets from the machine.
    Output,
}

impl Hook {
    /// The chain's name, and the hook's in nft's syntax.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Output => "output",
        }
    }

    /// Its number (`NF_INET_*`).
    #[must_use]
    pub fn number(self) -> u32 {
        match self {
            Self::Input => 1,
            Self::Output => 3,
        }
    }
}

/// A base chain's policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainPolicy {
    /// NF_ACCEPT.
    Accept,
    /// NF_DROP.
    Drop,
}

/// A rule: packets matching all of `matches` are counted (with `counter`), then `action`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// All must match; none matches every packet.
    pub matches: Vec<Match>,
    /// Counts the packets and bytes matched.
    pub counter: bool,
    /// What happens to them.
    pub action: Action,
    /// What it is for, which the status names it by.
    pub comment: String,
}

/// What a packet is matched on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Match {
    /// The interface it came in on, by name (`iifname`).
    InterfaceIn(&'static str),
    /// The interface it goes out of, by name (`oifname`).
    InterfaceOut(&'static str),
    /// Its connection's state, one of these (`ct state`).
    CtState(CtStates),
    /// ICMP (IPv4) of one of these types, in increasing order.
    Icmp(Vec<IcmpType>),
    /// ICMPv6 of one of these types, in increasing order.
    Icmpv6(Vec<Icmpv6Type>),
    /// Its transport protocol (`meta l4proto`).
    L4Proto(Protocol),
    /// TCP or UDP, from or to these ports.
    Ports {
        /// TCP or UDP.
        protocol: Protocol,
        /// Source ports (the protocol's own; `Ports`' is the same).
        source: Option<Ports>,
        /// Destination ports.
        destination: Option<Ports>,
    },
}

/// Connection tracking states, as `ct state`'s bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CtStates(u32);

impl CtStates {
    /// INVALID.
    pub const INVALID: Self = Self(1);
    /// ESTABLISHED.
    pub const ESTABLISHED: Self = Self(2);
    /// RELATED.
    pub const RELATED: Self = Self(4);
    /// ESTABLISHED or RELATED.
    pub const ESTABLISHED_RELATED: Self = Self(2 | 4);

    /// The bits (`NF_CT_STATE_*_BIT`), in host order like the kernel's register.
    #[must_use]
    pub fn bits(self) -> u32 {
        self.0
    }

    /// The states' names, in nft's order (the bits').
    #[must_use]
    pub fn names(self) -> Vec<&'static str> {
        [(1, "invalid"), (2, "established"), (4, "related")]
            .into_iter()
            .filter(|(bit, _)| self.0 & bit != 0)
            .map(|(_, name)| name)
            .collect()
    }
}

/// What a rule does with the packets it matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Accepted.
    Accept,
    /// Dropped.
    Drop,
    /// Refused with a TCP reset (TCP packets only).
    RejectTcpReset,
    /// Refused with an ICMP or ICMPv6 port unreachable (`reject`).
    RejectPortUnreachable,
    /// Logged to the kernel's log with this prefix, at most [`LOG_RATE`](super::LOG_RATE); the
    /// next rules decide.
    Log(&'static str),
}

impl Action {
    /// Whether it refuses packets: the drop and reject rules, which the status sums.
    #[must_use]
    pub fn blocks(&self) -> bool {
        matches!(
            self,
            Self::Drop | Self::RejectTcpReset | Self::RejectPortUnreachable
        )
    }
}

impl Rule {
    /// A rule of `matches`, counted or not, doing `action`, for what `comment` says.
    #[must_use]
    pub fn new(matches: Vec<Match>, counter: bool, action: Action, comment: &str) -> Self {
        Self {
            matches,
            counter,
            action,
            comment: comment.to_owned(),
        }
    }
}

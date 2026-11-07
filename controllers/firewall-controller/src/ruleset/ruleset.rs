//! The ruleset a configuration comes to.

use super::Action;
use super::Chain;
use super::ChainPolicy;
use super::CtStates;
use super::Hook;
use super::IcmpType;
use super::Icmpv6Type;
use super::Match;
use super::Rule;
use crate::policy::Allowed;
use crate::policy::FirewallConfig;
use crate::policy::Inbound;
use crate::policy::Outbound;
use crate::ports::Ports;
use crate::ports::Protocol;

/// The table's family, `inet` (IPv4 and IPv6).
pub const FAMILY: &str = "inet";
/// The table's name.
pub const TABLE: &str = "firewall-controller";
/// The prefix of the log lines of what the input chain blocks.
pub const LOG_PREFIX_IN: &str = "firewall-controller in: ";
/// The prefix of the log lines of what the output chain blocks.
pub const LOG_PREFIX_OUT: &str = "firewall-controller out: ";
/// The log lines' rate: per second, and the burst.
pub const LOG_RATE: (u64, u32) = (5, 10);

/// The table: its base chains, in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    /// At least `input`.
    pub chains: Vec<Chain>,
}

impl Ruleset {
    /// What `config` comes to; `None` when disabled: no table.
    #[must_use]
    pub fn of(config: &FirewallConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        let mut chains = vec![input(config)];
        if config.outbound == Outbound::Drop {
            chains.push(output(config));
        }
        Some(Self { chains })
    }

    /// Its rules, with their chains', in order.
    pub fn rules(&self) -> impl Iterator<Item = (Hook, &Rule)> {
        self.chains
            .iter()
            .flat_map(|chain| chain.rules.iter().map(|rule| (chain.hook, rule)))
    }
}

/// The rules accepting `allowed` to its destination ports, each counted.
fn allow(allowed: &Allowed) -> impl Iterator<Item = Rule> {
    let comment = allowed.to_string();
    allowed.ports().into_iter().map(move |ports| {
        let matches = vec![Match::Ports {
            protocol: ports.protocol(),
            source: None,
            destination: Some(ports),
        }];
        Rule::new(matches, true, Action::Accept, &comment)
    })
}

/// UDP from port `source` to port `destination`: DHCP's (67, 68) and DHCPv6's (547, 546).
fn dhcp(source: u32, destination: u32) -> Match {
    let port = |number| {
        let port = crate::ports::Port::try_from(number)
            .unwrap_or_else(|_| unreachable!("DHCP's ports are ports"));
        Ports::one(Protocol::Udp, port)
    };
    Match::Ports {
        protocol: Protocol::Udp,
        source: Some(port(source)),
        destination: Some(port(destination)),
    }
}

/// The input chain of `config`.
fn input(config: &FirewallConfig) -> Chain {
    if config.inbound == Inbound::Accept {
        return Chain {
            hook: Hook::Input,
            policy: ChainPolicy::Accept,
            rules: Vec::new(),
        };
    }
    use Icmpv6Type as V6;
    let mut rules = vec![
        Rule::new(
            vec![Match::InterfaceIn("lo")],
            false,
            Action::Accept,
            "loopback",
        ),
        Rule::new(
            vec![Match::CtState(CtStates::ESTABLISHED_RELATED)],
            true,
            Action::Accept,
            "established",
        ),
        Rule::new(
            vec![Match::CtState(CtStates::INVALID)],
            true,
            Action::Drop,
            "invalid",
        ),
        // Errors (path MTU discovery's too) and the neighbour discovery IPv6 needs.
        Rule::new(
            vec![Match::Icmpv6(vec![
                V6::DestinationUnreachable,
                V6::PacketTooBig,
                V6::TimeExceeded,
                V6::ParameterProblem,
                V6::MldListenerQuery,
                V6::NdRouterAdvert,
                V6::NdNeighborSolicit,
                V6::NdNeighborAdvert,
            ])],
            false,
            Action::Accept,
            "icmpv6",
        ),
        Rule::new(
            vec![Match::Icmp(vec![
                IcmpType::DestinationUnreachable,
                IcmpType::TimeExceeded,
                IcmpType::ParameterProblem,
            ])],
            false,
            Action::Accept,
            "icmp",
        ),
        // A DHCP server's replies, which conntrack does not relate to the broadcast request; a
        // DHCPv6 server's, to the multicast one (from its link-local address).
        Rule::new(vec![dhcp(67, 68)], false, Action::Accept, "dhcp"),
        Rule::new(vec![dhcp(547, 546)], false, Action::Accept, "dhcpv6"),
    ];
    if config.ping {
        rules.push(Rule::new(
            vec![Match::Icmp(vec![IcmpType::EchoRequest])],
            true,
            Action::Accept,
            "ping",
        ));
        rules.push(Rule::new(
            vec![Match::Icmpv6(vec![V6::EchoRequest])],
            true,
            Action::Accept,
            "ping",
        ));
    }
    rules.extend(config.allowed_inbound.items().iter().flat_map(allow));
    if config.log_drops {
        rules.push(Rule::new(
            Vec::new(),
            true,
            Action::Log(LOG_PREFIX_IN),
            "log",
        ));
    }
    if config.inbound == Inbound::Reject {
        rules.push(Rule::new(
            vec![Match::L4Proto(Protocol::Tcp)],
            true,
            Action::RejectTcpReset,
            "reject",
        ));
        rules.push(Rule::new(
            Vec::new(),
            true,
            Action::RejectPortUnreachable,
            "reject",
        ));
    } else {
        rules.push(Rule::new(Vec::new(), true, Action::Drop, "drop"));
    }
    Chain {
        hook: Hook::Input,
        policy: ChainPolicy::Drop,
        rules,
    }
}

/// The output chain of `config`, with [`Outbound::Drop`].
fn output(config: &FirewallConfig) -> Chain {
    use Icmpv6Type as V6;
    let mut rules = vec![
        Rule::new(
            vec![Match::InterfaceOut("lo")],
            false,
            Action::Accept,
            "loopback",
        ),
        Rule::new(
            vec![Match::CtState(CtStates::ESTABLISHED_RELATED)],
            true,
            Action::Accept,
            "established",
        ),
        Rule::new(
            vec![Match::CtState(CtStates::INVALID)],
            true,
            Action::Drop,
            "invalid",
        ),
        Rule::new(
            vec![Match::Icmpv6(vec![
                V6::MldListenerReport,
                V6::NdRouterSolicit,
                V6::NdNeighborSolicit,
                V6::NdNeighborAdvert,
                V6::Mld2ListenerReport,
            ])],
            false,
            Action::Accept,
            "icmpv6",
        ),
        Rule::new(vec![dhcp(68, 67)], false, Action::Accept, "dhcp"),
        Rule::new(vec![dhcp(546, 547)], false, Action::Accept, "dhcpv6"),
    ];
    rules.extend(config.allowed_outbound.items().iter().flat_map(allow));
    if config.log_drops {
        rules.push(Rule::new(
            Vec::new(),
            true,
            Action::Log(LOG_PREFIX_OUT),
            "log",
        ));
    }
    rules.push(Rule::new(Vec::new(), true, Action::Drop, "drop"));
    Chain {
        hook: Hook::Output,
        policy: ChainPolicy::Drop,
        rules,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::AllowedList;

    #[test]
    fn disabled_is_no_table() {
        let disabled = FirewallConfig {
            enabled: false,
            ..FirewallConfig::default()
        };
        assert_eq!(Ruleset::of(&disabled), None);
        assert!(
            Ruleset::of(&FirewallConfig::default()).is_some(),
            "on by default"
        );
    }

    #[test]
    fn the_policy_applies() {
        let config = FirewallConfig {
            allowed_inbound: AllowedList::try_from(vec!["dns".parse().unwrap()]).unwrap(),
            ping: true,
            log_drops: false,
            ..FirewallConfig::default()
        };
        let ruleset = Ruleset::of(&config).unwrap();
        assert_eq!(ruleset.chains.len(), 1, "outbound accept: no output chain");
        let comments: Vec<_> = ruleset
            .rules()
            .map(|(_, rule)| rule.comment.as_str())
            .collect();
        assert_eq!(
            comments,
            [
                "loopback",
                "established",
                "invalid",
                "icmpv6",
                "icmp",
                "dhcp",
                "dhcpv6",
                "ping",
                "ping",
                "dns",
                "dns",
                "drop"
            ]
        );
        assert!(
            ruleset
                .rules()
                .filter(|(_, rule)| rule.action.blocks())
                .all(|(_, rule)| rule.counter),
            "what blocks is counted"
        );
    }

    #[test]
    fn inbound_accept_filters_nothing_in() {
        let config = FirewallConfig {
            inbound: Inbound::Accept,
            outbound: Outbound::Drop,
            ..FirewallConfig::default()
        };
        let ruleset = Ruleset::of(&config).unwrap();
        assert_eq!(ruleset.chains[0].policy, ChainPolicy::Accept);
        assert!(ruleset.chains[0].rules.is_empty());
        assert_eq!(ruleset.chains[1].hook, Hook::Output);
        assert_eq!(ruleset.chains[1].policy, ChainPolicy::Drop);
    }
}

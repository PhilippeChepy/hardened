//! A [`Ruleset`] in nft's syntax, as `nft list table inet firewall-controller` shows it
//! (counters as plain `counter`): what the status reports, and what `nft -f` takes.

use std::fmt::Write as _;

use super::Action;
use super::ChainPolicy;
use super::FAMILY;
use super::LOG_RATE;
use super::Match;
use super::Rule;
use super::Ruleset;
use super::TABLE;

/// `ruleset` as nft lists it.
#[must_use]
pub fn render(ruleset: &Ruleset) -> String {
    let mut text = format!("table {FAMILY} {TABLE} {{\n");
    for (i, chain) in ruleset.chains.iter().enumerate() {
        if i > 0 {
            text.push('\n');
        }
        let policy = match chain.policy {
            ChainPolicy::Accept => "accept",
            ChainPolicy::Drop => "drop",
        };
        let name = chain.hook.name();
        let _ = writeln!(text, "\tchain {name} {{");
        let _ = writeln!(
            text,
            "\t\ttype filter hook {name} priority filter; policy {policy};"
        );
        for rule in &chain.rules {
            let _ = writeln!(text, "\t\t{}", rule_text(rule));
        }
        text.push_str("\t}\n");
    }
    text.push_str("}\n");
    text
}

/// `rule` on one line.
#[must_use]
pub fn rule_text(rule: &Rule) -> String {
    let mut words: Vec<String> = rule.matches.iter().map(match_text).collect();
    let counter = if rule.counter { "counter " } else { "" };
    words.push(match &rule.action {
        Action::Accept => format!("{counter}accept"),
        Action::Drop => format!("{counter}drop"),
        Action::RejectTcpReset => format!("{counter}reject with tcp reset"),
        Action::RejectPortUnreachable => format!("{counter}reject"),
        // Counting what the limit lets through, as nft lists it: `limit ... counter log`.
        Action::Log(prefix) => format!(
            "limit rate {}/second burst {} packets {counter}log prefix \"{prefix}\" level info",
            LOG_RATE.0, LOG_RATE.1
        ),
    });
    words.push(format!("comment \"{}\"", rule.comment));
    words.join(" ")
}

/// `names` as one value or an anonymous set.
fn values(names: &[&str]) -> String {
    match names {
        [one] => (*one).to_owned(),
        _ => format!("{{ {} }}", names.join(", ")),
    }
}

fn match_text(matched: &Match) -> String {
    match matched {
        Match::InterfaceIn(name) => format!("iifname \"{name}\""),
        Match::InterfaceOut(name) => format!("oifname \"{name}\""),
        Match::CtState(states) => format!("ct state {}", states.names().join(",")),
        Match::Icmp(types) => {
            let names: Vec<_> = types.iter().map(|t| t.name()).collect();
            format!("icmp type {}", values(&names))
        }
        Match::Icmpv6(types) => {
            let names: Vec<_> = types.iter().map(|t| t.name()).collect();
            format!("icmpv6 type {}", values(&names))
        }
        Match::L4Proto(protocol) => format!("meta l4proto {protocol}"),
        Match::Ports {
            protocol,
            source,
            destination,
        } => {
            let mut words = Vec::new();
            if let Some(source) = source {
                words.push(format!("{protocol} sport {}", source.range_text()));
            }
            if let Some(destination) = destination {
                words.push(format!("{protocol} dport {}", destination.range_text()));
            }
            words.join(" ")
        }
    }
}

#[cfg(test)]
/// The configurations of the golden rulesets (`golden/<name>.nft`).
pub fn golden_configs() -> Vec<(&'static str, crate::policy::FirewallConfig)> {
    use crate::policy::AllowedList;
    use crate::policy::FirewallConfig;
    use crate::policy::Inbound;
    use crate::policy::Outbound;

    let allowed = |items: &[&str]| {
        AllowedList::try_from(
            items
                .iter()
                .map(|item| item.parse().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap()
    };
    let reject = FirewallConfig {
        inbound: Inbound::Reject,
        allowed_inbound: allowed(&["ssh", "6000-6010/udp"]),
        ping: true,
        ..FirewallConfig::default()
    };
    let outbound = FirewallConfig {
        outbound: Outbound::Drop,
        allowed_outbound: allowed(&["dns", "https", "http", "ntp"]),
        ping: true,
        ..FirewallConfig::default()
    };
    let open = FirewallConfig {
        inbound: Inbound::Accept,
        ..FirewallConfig::default()
    };
    vec![
        ("default", FirewallConfig::default()),
        ("reject", reject),
        ("outbound", outbound),
        ("open", open),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ruleset::Ruleset;

    #[test]
    fn golden_rulesets() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ruleset/golden");
        let update = std::env::var_os("FIREWALL_UPDATE_GOLDEN").is_some();
        for (name, config) in golden_configs() {
            let text = render(&Ruleset::of(&config).unwrap());
            let path = dir.join(format!("{name}.nft"));
            if update {
                std::fs::write(&path, &text).unwrap();
            }
            let golden = std::fs::read_to_string(&path).unwrap();
            assert_eq!(
                text, golden,
                "{name} (FIREWALL_UPDATE_GOLDEN=1 rewrites them)"
            );
        }
    }
}

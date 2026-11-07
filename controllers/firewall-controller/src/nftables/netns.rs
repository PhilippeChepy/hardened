//! The rulesets applied to Linux's nf_tables, in a user and network namespace of their own
//! (`unshare -rn`): what the controller sends is taken, reads back, and `nft list` (when `nft`
//! is on the `PATH`) shows it exactly as the golden files say.

use std::env;
use std::process::Command;

use super::MessageKind;
use super::Messages;
use super::attr::Writer;
use super::flags;
use super::socket::NftError;
use super::socket::NftSocket;
use crate::ruleset::Ruleset;
use crate::ruleset::TABLE;
use crate::ruleset::text;

const TEST: &str = "nftables::netns::applies_in_a_network_namespace";
/// Unset in the launcher, set in the namespace.
const INSIDE: &str = "FIREWALL_CONTROLLER_TEST_NETNS";

#[test]
#[ignore = "needs unprivileged user namespaces (unshare -rn)"]
fn applies_in_a_network_namespace() {
    if env::var_os(INSIDE).is_some() {
        inside();
        return;
    }
    let status = Command::new("unshare")
        .args(["--user", "--map-root-user", "--net", "--"])
        .arg(env::current_exe().unwrap())
        .args(["--ignored", "--exact", "--nocapture", TEST])
        .env(INSIDE, "1")
        .status()
        .unwrap();
    assert!(
        status.success(),
        "test inside the namespace failed: {status}"
    );
}

/// `nft list table inet firewall-controller`, its counters' values left out; `None` without nft.
fn nft_list() -> Option<String> {
    let output = Command::new("nft")
        .args(["list", "table", "inet", TABLE])
        .output()
        .ok()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    // `counter packets N bytes M` as `counter`.
    let lines = text.lines().map(|line| {
        let words: Vec<_> = line.split(' ').collect();
        let mut out = Vec::new();
        let mut skip = 0;
        for (i, word) in words.iter().enumerate() {
            if skip > 0 {
                skip -= 1;
                continue;
            }
            out.push(*word);
            if word.trim_start() == "counter" && words.get(i + 1) == Some(&"packets") {
                skip = 4;
            }
        }
        out.join(" ") + "\n"
    });
    Some(lines.collect())
}

fn inside() {
    let mut socket = NftSocket::open().unwrap();
    assert!(!socket.table_exists().unwrap());
    let mut generation = socket.generation().unwrap();
    let has_nft = Command::new("nft").arg("--version").output().is_ok();
    if !has_nft {
        eprintln!("nft is not on the PATH: the listings are not compared");
    }
    for (name, config) in text::golden_configs() {
        let ruleset = Ruleset::of(&config).unwrap();
        let applied = socket
            .apply(Some(&ruleset))
            .unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(applied > generation, "{name}: a new generation");
        generation = applied;
        assert!(socket.table_exists().unwrap());
        let rules = socket.rules().unwrap();
        let expected: Vec<_> = ruleset
            .rules()
            .map(|(hook, rule)| (hook.name(), rule.comment.as_str()))
            .collect();
        let read: Vec<_> = rules
            .iter()
            .map(|rule| (rule.chain.as_str(), rule.comment.as_str()))
            .collect();
        assert_eq!(read, expected, "{name}");
        assert!(
            rules
                .iter()
                .all(|rule| rule.handle > 0 && rule.packets == 0)
        );
        if has_nft {
            assert_eq!(nft_list().unwrap(), text::render(&ruleset), "{name}");
        }
        eprintln!(
            "{name}: applied, {} rules, generation {applied}",
            rules.len()
        );
    }

    // A refused batch changes nothing: the table stays as it was.
    let before = socket.rules().unwrap();
    let mut batch = Messages::new(socket.next_sequence());
    batch.push(super::BATCH_BEGIN, flags::REQUEST, 0, super::SUBSYSTEM, &[]);
    let mut table = Writer::new();
    table.string(1, TABLE);
    batch.nftables(
        MessageKind::DelTable,
        flags::REQUEST | flags::ACK,
        &table.into_bytes(),
    );
    let mut rule = Writer::new();
    rule.string(1, TABLE).string(2, "missing").nested(4, |_| {});
    batch.nftables(
        MessageKind::NewRule,
        flags::REQUEST | flags::ACK | flags::CREATE | flags::APPEND,
        &rule.into_bytes(),
    );
    batch.label("adding a rule to a missing chain");
    batch.push(super::BATCH_END, flags::REQUEST, 0, super::SUBSYSTEM, &[]);
    match socket.apply_batch(&batch) {
        Err(NftError::Refused { what, error }) => {
            assert_eq!(what, "adding a rule to a missing chain");
            assert_eq!(error.raw_os_error(), Some(2), "ENOENT");
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(socket.rules().unwrap(), before, "aborted");

    // Disabled: no table, twice in a row.
    socket.apply(None).unwrap();
    assert!(!socket.table_exists().unwrap());
    assert!(socket.rules().unwrap().is_empty());
    socket.apply(None).unwrap();
    assert!(!socket.table_exists().unwrap());
}

const TRAFFIC_TEST: &str = "nftables::netns::dhcp_and_neighbour_discovery_pass_the_default_policy";
/// The role in the traffic test: unset (launcher), `inside` (behind the firewall) or `peer` (the
/// network, in a namespace of its own).
const TRAFFIC_ROLE: &str = "FIREWALL_CONTROLLER_TEST_TRAFFIC";
/// The veth pair's ends: ours, behind the firewall, and the network's.
const OURS: &str = "fw0";
const PEER: &str = "peer0";

/// The traffic a host behind the default policy (the first boot's) gets from its network, over
/// a veth pair whose other end is in a nested namespace: a DHCP server's unicast reply (from
/// port 67 to 68), a DHCPv6 server's (547 to 546, link-local: the neighbour discovery's
/// solicitation and advertisement come first), a router advertisement whose prefix SLAAC takes;
/// and UDP to another port, dropped and counted. Needs `ip` (iproute2) on the `PATH`.
#[test]
#[ignore = "needs unprivileged user namespaces (unshare -rn) and iproute2"]
fn dhcp_and_neighbour_discovery_pass_the_default_policy() {
    match env::var(TRAFFIC_ROLE).as_deref() {
        Ok("inside") => behind_the_firewall(),
        Ok("peer") => network(),
        _ => {
            let status = rerun_traffic(&["--user", "--map-root-user", "--net"], "inside")
                .status()
                .unwrap();
            assert!(
                status.success(),
                "test inside the namespace failed: {status}"
            );
        }
    }
}

fn rerun_traffic(namespaces: &[&str], role: &str) -> Command {
    let mut command = Command::new("unshare");
    command
        .args(namespaces)
        .arg("--")
        .arg(env::current_exe().unwrap())
        .args(["--ignored", "--exact", "--nocapture", TRAFFIC_TEST])
        .env(TRAFFIC_ROLE, role);
    command
}

/// Runs `ip args`, which must succeed.
fn ip(args: &str) -> String {
    let output = Command::new("ip").args(args.split(' ')).output().unwrap();
    assert!(
        output.status.success(),
        "ip {args}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

/// The index of the interface `name`.
fn index(name: &str) -> u32 {
    let line = ip(&format!("-o link show {name}"));
    line.split(':').next().unwrap().trim().parse().unwrap()
}

fn behind_the_firewall() {
    use std::net::Ipv6Addr;
    use std::net::SocketAddrV6;
    use std::net::UdpSocket;
    use std::time::Duration;
    use std::time::Instant;

    use crate::policy::FirewallConfig;

    if Command::new("ip").arg("-V").output().is_err() {
        eprintln!("ip (iproute2) is not on the PATH: skipped");
        return;
    }
    let mut socket = NftSocket::open().unwrap();
    let ruleset = Ruleset::of(&FirewallConfig::default()).unwrap();
    socket.apply(Some(&ruleset)).unwrap();

    let receiver = |address: &str| {
        let socket = UdpSocket::bind(address).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        socket
    };
    let dhcp = receiver("0.0.0.0:68");
    let dhcpv6 = receiver("[::]:546");
    let other = receiver("0.0.0.0:5000");

    struct Kill(std::process::Child);
    impl Drop for Kill {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let peer = Kill(rerun_traffic(&["--net"], "peer").spawn().unwrap());
    let pid = peer.0.id();
    ip(&format!("link add {OURS} type veth peer name {PEER}"));
    ip(&format!("link set {PEER} netns {pid}"));
    ip(&format!("addr add 10.9.0.2/24 dev {OURS}"));
    ip(&format!("-6 addr add fe80::2/64 dev {OURS} nodad"));
    ip(&format!("link set {OURS} up"));

    let wait = |socket: &UdpSocket, what: &str| {
        let deadline = Instant::now() + Duration::from_secs(15);
        let mut buffer = [0; 64];
        while Instant::now() < deadline {
            if let Ok((len, from)) = socket.recv_from(&mut buffer) {
                assert_eq!(&buffer[..len], what.as_bytes());
                return from;
            }
        }
        panic!("no {what} packet came in");
    };
    let from = wait(&dhcp, "dhcp");
    assert_eq!(from.to_string(), "10.9.0.1:67");
    let from = wait(&dhcpv6, "dhcpv6");
    let link_local = SocketAddrV6::new(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1), 547, 0, 0);
    assert_eq!(
        (from.ip(), from.port()),
        (std::net::IpAddr::V6(*link_local.ip()), 547),
        "after the neighbour discovery"
    );
    eprintln!("DHCP's and DHCPv6's replies came in");

    // SLAAC from the router advertisement.
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if ip(&format!("-6 addr show dev {OURS}")).contains("inet6 fd00:9:") {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "no address from the router advertisement"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("the router advertisement's prefix was taken");

    // The peer keeps sending to port 5000: dropped, counted.
    std::thread::sleep(Duration::from_secs(1));
    let mut buffer = [0; 64];
    assert!(
        other.recv_from(&mut buffer).is_err(),
        "port 5000 is not allowed"
    );
    let rules = socket.rules().unwrap();
    let dropped = rules.iter().find(|rule| rule.comment == "drop").unwrap();
    assert!(dropped.packets > 0, "{rules:?}");
    eprintln!("UDP to port 5000 was dropped: {} packets", dropped.packets);
}

/// The network: waits for its end of the pair, then sends DHCP's and DHCPv6's replies, router
/// advertisements and UDP to port 5000, every 100 ms, until killed.
fn network() {
    use std::net::Ipv6Addr;
    use std::net::SocketAddrV6;
    use std::net::UdpSocket;
    use std::time::Duration;
    use std::time::Instant;

    use rustix::net::AddressFamily;
    use rustix::net::SendFlags;
    use rustix::net::SocketType;
    use rustix::net::ipproto;
    use rustix::net::sockopt;

    let deadline = Instant::now() + Duration::from_secs(15);
    while Command::new("ip")
        .args(["link", "show", PEER])
        .output()
        .is_ok_and(|output| !output.status.success())
    {
        assert!(Instant::now() < deadline, "{PEER} never came");
        std::thread::sleep(Duration::from_millis(50));
    }
    ip(&format!("addr add 10.9.0.1/24 dev {PEER}"));
    ip(&format!("-6 addr add fe80::1/64 dev {PEER} nodad"));
    ip(&format!("link set {PEER} up"));
    let scope = index(PEER);
    let local = |last| Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, last);

    let dhcp = UdpSocket::bind("10.9.0.1:67").unwrap();
    let dhcpv6 = UdpSocket::bind(SocketAddrV6::new(local(1), 547, 0, scope)).unwrap();
    let other = UdpSocket::bind("10.9.0.1:0").unwrap();
    // A router advertisement: router lifetime 1800 s, the prefix fd00:9::/64, on-link and
    // autonomous (RFC 4861 4.2, 4.6.2). The kernel computes the checksum.
    let mut advert = vec![134, 0, 0, 0, 64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0];
    advert.extend([3, 4, 64, 0xc0]);
    advert.extend(86_400u32.to_be_bytes());
    advert.extend(14_400u32.to_be_bytes());
    advert.extend([0; 4]);
    advert.extend(Ipv6Addr::new(0xfd00, 9, 0, 0, 0, 0, 0, 0).octets());
    let raw =
        rustix::net::socket(AddressFamily::INET6, SocketType::RAW, Some(ipproto::ICMPV6)).unwrap();
    sockopt::set_ipv6_unicast_hops(&raw, Some(255)).unwrap();
    rustix::net::bind(&raw, &SocketAddrV6::new(local(1), 0, 0, scope)).unwrap();
    // To our address, as a solicited one may be: rustix 1.1 sets IPV6_MULTICAST_HOPS at the
    // wrong level, and an advertisement must come with a hop limit of 255.
    let router_to = SocketAddrV6::new(local(2), 0, 0, scope);
    loop {
        // Before the neighbour is known, sends may fail: tried again.
        let _ = dhcp.send_to(b"dhcp", "10.9.0.2:68");
        let _ = dhcpv6.send_to(b"dhcpv6", SocketAddrV6::new(local(2), 546, 0, scope));
        let _ = other.send_to(b"other", "10.9.0.2:5000");
        let _ = rustix::net::sendto(&raw, &advert, SendFlags::empty(), &router_to);
        std::thread::sleep(Duration::from_millis(100));
    }
}

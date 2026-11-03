//! State shared by the DHCP clients of all interfaces, the static configurations and the API:
//! `resolv.conf` is rewritten whenever what they say changes.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use controllers_helpers::DomainName;
use controllers_helpers::atomic_file;
use network_controller::DnsSettings;
use network_controller::StaticIpv4;
use network_controller::network;
use tokio::sync::watch;

use crate::dhcp::Lease;
use crate::persisted_state;
use crate::prefix_len::PrefixLen;
use crate::resolv_conf;

/// State shared by the DHCP clients of all interfaces and the API.
pub struct Shared {
    /// Where `resolv.conf` is written.
    resolv_conf: PathBuf,
    /// Where the DNS override is persisted.
    state_file: PathBuf,
    next_rank: AtomicU32,
    state: Mutex<State>,
    /// Number of interfaces currently holding a lease or configured statically.
    pub bound: watch::Sender<usize>,
    /// What DHCP offered, as the API serves it.
    pub offered: watch::Sender<network::State>,
}

impl Shared {
    /// No interface and no lease yet; `resolv.conf` is written at `resolv_conf`, the DNS
    /// override persisted in `state_file`.
    #[must_use]
    pub fn new(resolv_conf: PathBuf, state_file: PathBuf) -> Self {
        Self {
            resolv_conf,
            state_file,
            next_rank: AtomicU32::new(0),
            state: Mutex::new(State::default()),
            bound: watch::Sender::new(0),
            offered: watch::Sender::new(network::State::default()),
        }
    }

    fn state_lock(&self) -> MutexGuard<'_, State> {
        // Only a bug panics with the lock held; the state, whole values assigned, is kept.
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Registers the interface `name` of `index` as one DHCP runs on.
    pub fn add_interface(&self, index: u32, name: &str) {
        self.update(|state| {
            state.interfaces.insert(index, name.to_owned());
        });
    }

    /// Forgets the interface of `index`, its lease or static configuration and its resolver, as
    /// if it had lost them: the interface is gone, and the kernel removed its addresses and
    /// routes with it.
    pub fn remove_interface(&self, index: u32) {
        self.update(|state| {
            state.interfaces.remove(&index);
            state.by_rank.retain(|_, bound| bound.index != index);
            state
                .statics
                .retain(|_, configured| configured.index != index);
            state.interface_dns.remove(&index);
        });
    }

    /// Forgets that DHCP runs on the interface of `index`: its client stopped, having given up
    /// its lease.
    pub fn remove_dhcp_interface(&self, index: u32) {
        self.update(|state| {
            state.interfaces.remove(&index);
        });
    }

    /// Sets the resolver configuration of the interface of `index`: each list, when not empty,
    /// replaces what its lease gives.
    pub fn set_interface_dns(&self, index: u32, dns: DnsSettings) {
        self.update(|state| {
            if dns == DnsSettings::default() {
                state.interface_dns.remove(&index);
            } else {
                state.interface_dns.insert(index, dns);
            }
        });
    }

    /// Records the static configuration of the interface `name` of `index`, of `rank`.
    pub fn bind_static(&self, rank: u32, index: u32, name: &str, addresses: StaticIpv4) {
        self.update(|state| {
            let configured = Configured {
                index,
                interface: name.to_owned(),
                addresses,
            };
            state.statics.insert(rank, configured);
        });
    }

    /// Forgets the static configuration of `rank`.
    pub fn unbind_static(&self, rank: u32) {
        self.update(|state| {
            state.statics.remove(&rank);
        });
    }

    /// Whether the interface of `index` holds a lease, and the name servers it gives
    /// `resolv.conf` (before `settings.dns`).
    #[must_use]
    pub fn interface_status(&self, index: u32) -> (bool, Vec<IpAddr>) {
        let state = self.state_lock();
        let leased = state.by_rank.values().any(|bound| bound.index == index);
        let name_servers = state
            .sources()
            .into_iter()
            .filter(|source| source.index == index)
            .flat_map(|source| source.name_servers)
            .collect();
        (leased, name_servers)
    }

    /// The rank of the next interface to get a lease: 0 for the first one. The lowest rank
    /// holding a lease is the primary interface's, so a new or re-plugged interface ranks after
    /// those already there.
    #[must_use]
    pub fn next_rank(&self) -> u32 {
        self.next_rank.fetch_add(1, Ordering::Relaxed)
    }

    /// Records the lease of the interface `name` of `index`, of `rank`.
    pub fn bind(&self, rank: u32, index: u32, name: &str, lease: Lease) {
        self.update(|state| {
            let bound = Bound {
                index,
                interface: name.to_owned(),
                lease,
            };
            state.by_rank.insert(rank, bound);
        });
    }

    /// Forgets the lease of `rank`.
    pub fn unbind(&self, rank: u32) {
        self.update(|state| {
            state.by_rank.remove(&rank);
        });
    }

    /// Replaces the nameservers and search domains learned through DHCP with those of `dns`
    /// (each list when not empty), now and across renewals.
    pub fn set_dns_override(&self, dns: DnsSettings) {
        self.update(|state| state.set_dns_override(dns));
    }

    /// Persists `dns`, then sets it as the override. Persisted first, with the lock held so that
    /// concurrent configurations persist in order: an override that would not survive a restart
    /// is refused.
    pub fn configure_dns(&self, dns: DnsSettings) -> anyhow::Result<()> {
        self.update(|state| {
            persisted_state::save(&self.state_file, &dns)?;
            state.set_dns_override(dns);
            Ok(())
        })
    }

    /// Writes `resolv.conf` if it was not yet, e.g. before any lease or override.
    pub fn refresh(&self) {
        self.update(|_| {});
    }

    /// Applies `change`, then rewrites `resolv.conf` if it changed, and notifies waiters. The
    /// file is written with the lock held, so in order.
    fn update<R>(&self, change: impl FnOnce(&mut State) -> R) -> R {
        let (result, count, offered) = {
            let mut state = self.state_lock();
            let result = change(&mut state);
            let resolver = state.resolver();
            let resolv_conf = resolv_conf::render(&resolver.name_servers, &resolver.search_list);
            if state.written.as_ref() != Some(&resolv_conf) {
                state.written = self.write(&resolv_conf).then_some(resolv_conf);
            }
            (
                result,
                state.by_rank.len() + state.statics.len(),
                state.offered(),
            )
        };
        self.bound.send_replace(count);
        self.offered.send_if_modified(|current| {
            let changed = *current != offered;
            *current = offered;
            changed
        });
        result
    }

    /// Writes `resolv.conf`; returns whether it was written.
    fn write(&self, resolv_conf: &str) -> bool {
        if let Err(err) = atomic_file::write(&self.resolv_conf, resolv_conf.as_bytes(), 0o644) {
            tracing::error!(
                path = %self.resolv_conf.display(),
                "writing resolv.conf: {err}"
            );
            return false;
        }
        true
    }

    /// The primary interface: the first to get a lease that it still holds.
    #[cfg(test)]
    #[must_use]
    pub fn primary(&self) -> Option<String> {
        let state = self.state_lock();
        state
            .by_rank
            .values()
            .next()
            .map(|bound| bound.interface.clone())
    }

    /// Logs the interfaces, leased ones first by rank, and the name servers.
    pub fn log(&self) {
        let state = self.state_lock();
        for Bound {
            interface, lease, ..
        } in state.by_rank.values()
        {
            tracing::info!(
                interface,
                address = %lease.address,
                prefix = lease.prefix_len.get(),
                gateway = ?default_gateway(lease),
                mtu = ?lease.mtu,
                "network interface"
            );
        }
        for Configured {
            interface,
            addresses,
            ..
        } in state.statics.values()
        {
            tracing::info!(
                interface,
                addresses = ?addresses.addresses().iter().map(ToString::to_string).collect::<Vec<_>>(),
                gateway = ?addresses.gateway(),
                "network interface configured statically"
            );
        }
        for name in state.unbound() {
            tracing::warn!(interface = name, "network interface without a lease");
        }
        tracing::info!(nameservers = ?state.resolver().name_servers, "DNS configured");
    }
}

#[derive(Default)]
struct State {
    /// Names of the interfaces DHCP runs on, by index.
    interfaces: BTreeMap<u32, String>,
    /// Current leases by rank (bind order): the first entry is the primary interface.
    by_rank: BTreeMap<u32, Bound>,
    /// Static configurations by rank, which they share with leases.
    statics: BTreeMap<u32, Configured>,
    /// The interfaces' own resolver configurations, by index.
    interface_dns: BTreeMap<u32, DnsSettings>,
    /// Replaces the leased nameservers and search domains (each list when not empty).
    dns_override: DnsSettings,
    /// The `resolv.conf` last written, not to rewrite it needlessly.
    written: Option<String>,
}

/// An interface holding a lease.
struct Bound {
    index: u32,
    interface: String,
    lease: Lease,
}

/// An interface configured statically.
struct Configured {
    index: u32,
    interface: String,
    addresses: StaticIpv4,
}

/// What an interface gives `resolv.conf`, before `settings.dns`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Source {
    index: u32,
    name_servers: Vec<IpAddr>,
    search_list: Vec<DomainName>,
}

impl Source {
    /// What `lease`, of the interface of `index`, gives: its search list, or its domain name.
    #[must_use]
    fn leased(index: u32, lease: &Lease) -> Self {
        let search_list = if lease.search.is_empty() {
            lease.domain_name.iter().cloned().collect()
        } else {
            lease.search.clone()
        };
        Self {
            index,
            name_servers: lease.nameservers.iter().copied().map(IpAddr::V4).collect(),
            search_list,
        }
    }
}

impl State {
    /// What DHCP offered, as the API serves it.
    #[must_use]
    fn offered(&self) -> network::State {
        let mut ntp_servers = Vec::new();
        for server in self
            .by_rank
            .values()
            .flat_map(|bound| &bound.lease.ntp_servers)
        {
            let server = server.to_string();
            if !ntp_servers.contains(&server) {
                ntp_servers.push(server);
            }
        }
        network::State {
            dhcp_hostname: self
                .by_rank
                .values()
                .next()
                .and_then(|bound| bound.lease.hostname.as_ref())
                .map(|name| name.as_str().to_owned()),
            ntp_servers,
        }
    }

    fn set_dns_override(&mut self, dns: DnsSettings) {
        if self.dns_override != dns {
            tracing::info!(
                nameservers = ?dns.name_servers,
                search = ?dns.search_list,
                "DNS override"
            );
            self.dns_override = dns;
        }
    }

    /// What goes into `resolv.conf`.
    fn resolver(&self) -> DnsSettings {
        resolver_config(&self.dns_override, &self.sources())
    }

    /// What each configured interface gives `resolv.conf`, by rank: its own resolver
    /// configuration's lists, or its lease's.
    fn sources(&self) -> Vec<Source> {
        let leased = (self.by_rank.iter())
            .map(|(rank, bound)| (*rank, Source::leased(bound.index, &bound.lease)));
        let configured = self.statics.iter().map(|(rank, configured)| {
            let source = Source {
                index: configured.index,
                name_servers: Vec::new(),
                search_list: Vec::new(),
            };
            (*rank, source)
        });
        let mut sources: Vec<(u32, Source)> = leased.chain(configured).collect();
        sources.sort_by_key(|(rank, _)| *rank);
        sources
            .into_iter()
            .map(|(_, mut source)| {
                if let Some(dns) = self.interface_dns.get(&source.index) {
                    if !dns.name_servers.is_empty() {
                        source.name_servers.clone_from(&dns.name_servers);
                    }
                    if !dns.search_list.is_empty() {
                        source.search_list.clone_from(&dns.search_list);
                    }
                }
                source
            })
            .collect()
    }

    /// Interfaces DHCP runs on without a lease.
    fn unbound(&self) -> impl Iterator<Item = &str> {
        self.interfaces
            .iter()
            .filter(|(index, _)| !self.by_rank.values().any(|bound| bound.index == **index))
            .map(|(_, name)| name.as_str())
    }
}

/// The gateway of the default route of `lease`, if any.
fn default_gateway(lease: &Lease) -> Option<Ipv4Addr> {
    lease
        .routes()
        .iter()
        .find(|route| route.prefix_len == PrefixLen::ZERO)
        .and_then(|route| route.gateway)
}

/// Nameservers and search domains from the interfaces' `sources` (primary first); each
/// configured list replaces theirs.
fn resolver_config(configured: &DnsSettings, sources: &[Source]) -> DnsSettings {
    let mut resolver = configured.clone();
    if resolver.name_servers.is_empty() {
        for source in sources {
            resolver
                .name_servers
                .extend_from_slice(&source.name_servers);
        }
    }
    if resolver.search_list.is_empty() {
        for source in sources {
            resolver.search_list.extend_from_slice(&source.search_list);
        }
    }
    resolver
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;
    use std::path::Path;

    use tokio::time::Instant;

    use super::*;

    pub fn lease(nameservers: &[[u8; 4]], domain: Option<&str>, search: &[&str]) -> Lease {
        Lease {
            address: Ipv4Addr::new(10, 0, 0, 5),
            prefix_len: PrefixLen::new(24).unwrap(),
            server: Ipv4Addr::new(10, 0, 0, 1),
            router: Some(Ipv4Addr::new(10, 0, 0, 1)),
            classless_routes: Vec::new(),
            nameservers: nameservers.iter().copied().map(Ipv4Addr::from).collect(),
            ntp_servers: vec![Ipv4Addr::new(10, 0, 0, 4)],
            domain_name: domain.map(|domain| domain.parse().unwrap()),
            search: search
                .iter()
                .map(|domain| domain.parse().unwrap())
                .collect(),
            hostname: Some("web-1".parse().unwrap()),
            mtu: Some(1460),
            timers: None,
            start: Instant::now(),
        }
    }

    pub fn shared(dir: &Path) -> Shared {
        Shared::new(dir.join("resolv.conf"), dir.join("state.json"))
    }

    fn address(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    #[test]
    fn resolver_config_merges_leases() {
        let primary = lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]);
        let secondary = lease(
            &[[10, 1, 0, 2]],
            Some("ignored.internal"),
            &["b.internal", "c.internal"],
        );
        let sources = [Source::leased(2, &primary), Source::leased(3, &secondary)];
        let resolver = resolver_config(&DnsSettings::default(), &sources);
        assert_eq!(
            resolver.name_servers,
            [address("10.0.0.2"), address("10.1.0.2")]
        );
        assert_eq!(
            resolver.search_list,
            ["a.internal", "b.internal", "c.internal"].map(|d| d.parse().unwrap())
        );

        let configured = DnsSettings {
            name_servers: vec![address("1.1.1.1")],
            ..DnsSettings::default()
        };
        let resolver = resolver_config(&configured, &sources[..1]);
        assert_eq!(resolver.name_servers, configured.name_servers);
        assert_eq!(
            resolver.search_list,
            [primary.domain_name.clone().unwrap()],
            "search domains still come from DHCP"
        );

        let configured = DnsSettings {
            search_list: vec!["corp.example".parse().unwrap()],
            ..DnsSettings::default()
        };
        let resolver = resolver_config(&configured, &sources[..1]);
        assert_eq!(
            resolver.name_servers,
            [address("10.0.0.2")],
            "nameservers still come from DHCP"
        );
        assert_eq!(resolver.search_list, configured.search_list);
    }

    #[test]
    fn state_follows_the_primary_interface() {
        let dir = tempfile::tempdir().unwrap();
        let shared = shared(dir.path());
        for (index, name) in [(2, "eth0"), (3, "eth1"), (4, "eth2")] {
            shared.add_interface(index, name);
        }
        shared.bind(
            0,
            3,
            "eth1",
            lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]),
        );
        shared.bind(
            1,
            2,
            "eth0",
            Lease {
                hostname: None,
                ..lease(&[[10, 1, 0, 2]], None, &[])
            },
        );
        assert_eq!(shared.primary().as_deref(), Some("eth1"));
        let state = shared.offered.borrow().clone();
        assert_eq!(state.dhcp_hostname.unwrap(), "web-1");
        assert_eq!(
            state.ntp_servers,
            ["10.0.0.4"],
            "merged, without duplicates"
        );
        assert_eq!(
            fs::read_to_string(dir.path().join("resolv.conf")).unwrap(),
            "# Generated by network-controller.\nnameserver 10.0.0.2\nnameserver 10.1.0.2\n\
             search a.internal\n"
        );
        assert_eq!(*shared.bound.borrow(), 2);

        shared.unbind(0);
        assert_eq!(shared.primary().as_deref(), Some("eth0"));
        assert_eq!(shared.offered.borrow().clone().dhcp_hostname, None);
        assert_eq!(*shared.bound.borrow(), 1);
    }

    #[test]
    fn removed_interface_loses_its_lease() {
        let dir = tempfile::tempdir().unwrap();
        let shared = shared(dir.path());
        shared.add_interface(2, "eth0");
        shared.add_interface(3, "eth1");
        let primary = lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]);
        shared.bind(shared.next_rank(), 2, "eth0", primary);
        let secondary = Lease {
            ntp_servers: vec![Ipv4Addr::new(10, 1, 0, 4)],
            ..lease(&[[10, 1, 0, 2]], None, &[])
        };
        shared.bind(shared.next_rank(), 3, "eth1", secondary);

        shared.remove_interface(2);
        assert_eq!(shared.primary().as_deref(), Some("eth1"));
        assert_eq!(shared.offered.borrow().clone().ntp_servers, ["10.1.0.4"]);
        assert_eq!(
            fs::read_to_string(dir.path().join("resolv.conf")).unwrap(),
            "# Generated by network-controller.\nnameserver 10.1.0.2\n"
        );
        assert_eq!(*shared.bound.borrow(), 1);

        // Re-plugged under the same name, with a new index: it ranks after eth1.
        shared.add_interface(5, "eth0");
        shared.bind(
            shared.next_rank(),
            5,
            "eth0",
            lease(&[[10, 0, 0, 2]], None, &[]),
        );
        assert_eq!(shared.primary().as_deref(), Some("eth1"));
        assert_eq!(*shared.bound.borrow(), 2);
        shared.remove_interface(3);
        assert_eq!(shared.primary().as_deref(), Some("eth0"));
        shared.remove_interface(5);
        assert_eq!(shared.primary(), None);
        assert_eq!(*shared.bound.borrow(), 0);
    }

    #[test]
    fn writes_resolv_conf_before_any_lease() {
        let dir = tempfile::tempdir().unwrap();
        let shared = shared(dir.path());
        shared.refresh();
        assert_eq!(shared.offered.borrow().clone(), network::State::default());
        assert_eq!(
            fs::read_to_string(dir.path().join("resolv.conf")).unwrap(),
            "# Generated by network-controller.\n"
        );
    }

    #[test]
    fn dns_override_survives_lease_updates() {
        let dir = tempfile::tempdir().unwrap();
        let resolv_conf = || fs::read_to_string(dir.path().join("resolv.conf")).unwrap();
        let shared = shared(dir.path());
        shared.bind(
            0,
            2,
            "eth0",
            lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]),
        );

        shared.set_dns_override(DnsSettings {
            name_servers: vec![address("192.0.2.53")],
            search_list: vec!["corp.example".parse().unwrap()],
        });
        let overridden =
            "# Generated by network-controller.\nnameserver 192.0.2.53\nsearch corp.example\n";
        assert_eq!(resolv_conf(), overridden);
        shared.bind(
            0,
            2,
            "eth0",
            lease(&[[10, 0, 0, 3]], Some("a.internal"), &[]),
        );
        assert_eq!(resolv_conf(), overridden, "a renewal keeps the override");

        shared.set_dns_override(DnsSettings::default());
        assert_eq!(
            resolv_conf(),
            "# Generated by network-controller.\nnameserver 10.0.0.3\nsearch a.internal\n",
            "back to DHCP"
        );
    }

    #[test]
    fn static_configurations_and_interface_resolvers() {
        let dir = tempfile::tempdir().unwrap();
        let resolv_conf = || fs::read_to_string(dir.path().join("resolv.conf")).unwrap();
        let shared = shared(dir.path());
        shared.add_interface(2, "eth0");
        shared.bind(
            0,
            2,
            "eth0",
            lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]),
        );
        let addresses = StaticIpv4::new(vec!["192.0.2.10/24".parse().unwrap()], None).unwrap();
        shared.bind_static(1, 3, "eth1", addresses);
        assert_eq!(*shared.bound.borrow(), 2);
        assert_eq!(
            resolv_conf(),
            "# Generated by network-controller.\nnameserver 10.0.0.2\nsearch a.internal\n",
            "a static configuration without a resolver adds nothing"
        );

        // Each interface's own lists replace its lease's; resolv.conf drops duplicates.
        shared.set_interface_dns(
            3,
            DnsSettings {
                name_servers: vec![address("192.0.2.53"), address("10.0.0.2")],
                search_list: vec!["corp.example".parse().unwrap()],
            },
        );
        shared.set_interface_dns(
            2,
            DnsSettings {
                name_servers: vec![address("10.0.0.3")],
                ..DnsSettings::default()
            },
        );
        assert_eq!(
            resolv_conf(),
            "# Generated by network-controller.\nnameserver 10.0.0.3\nnameserver 192.0.2.53\n\
             nameserver 10.0.0.2\nsearch a.internal corp.example\n"
        );
        assert_eq!(
            shared.interface_status(3),
            (false, vec![address("192.0.2.53"), address("10.0.0.2")])
        );
        assert_eq!(
            shared.interface_status(2),
            (true, vec![address("10.0.0.3")])
        );

        // settings.dns replaces them all.
        shared.set_dns_override(DnsSettings {
            name_servers: vec![address("1.1.1.1")],
            ..DnsSettings::default()
        });
        assert!(
            resolv_conf().contains("nameserver 1.1.1.1\nsearch"),
            "{}",
            resolv_conf()
        );

        shared.unbind_static(1);
        assert_eq!(*shared.bound.borrow(), 1);
        shared.remove_interface(3);
        assert_eq!(shared.interface_status(3), (false, Vec::new()));
        shared.remove_dhcp_interface(2);
        shared.unbind(0);
        assert_eq!(*shared.bound.borrow(), 0);
    }
}

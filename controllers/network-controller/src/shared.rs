//! State shared by the DHCP clients of all interfaces and the API: `resolv.conf` is rewritten
//! whenever what they say changes.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::MutexGuard;
use std::sync::PoisonError;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering;

use controllers_helpers::atomic_file;
use network_controller::DnsSettings;
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
    /// Number of interfaces currently holding a lease.
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

    /// Forgets the interface of `index` and its lease, as if it had lost it: the interface is
    /// gone, and the kernel removed its addresses and routes with it.
    pub fn remove_interface(&self, index: u32) {
        self.update(|state| {
            state.interfaces.remove(&index);
            state.by_rank.retain(|_, bound| bound.index != index);
        });
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
            (result, state.by_rank.len(), state.offered())
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
        let leases: Vec<&Lease> = self.by_rank.values().map(|bound| &bound.lease).collect();
        resolver_config(&self.dns_override, &leases)
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

/// Nameservers and search domains from `leases` (primary first); each configured list replaces
/// the leased one.
fn resolver_config(configured: &DnsSettings, leases: &[&Lease]) -> DnsSettings {
    let mut resolver = configured.clone();
    if resolver.name_servers.is_empty() {
        for lease in leases {
            let servers = lease.nameservers.iter().map(|&server| IpAddr::V4(server));
            resolver.name_servers.extend(servers);
        }
    }
    if resolver.search_list.is_empty() {
        for lease in leases {
            if lease.search.is_empty() {
                resolver
                    .search_list
                    .extend(lease.domain_name.iter().cloned());
            } else {
                resolver.search_list.extend_from_slice(&lease.search);
            }
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
        let resolver = resolver_config(&DnsSettings::default(), &[&primary, &secondary]);
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
        let resolver = resolver_config(&configured, &[&primary]);
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
        let resolver = resolver_config(&configured, &[&primary]);
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
}

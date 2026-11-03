//! The physical Ethernet interfaces network-controller configures, by index: a link that
//! disappears takes its DHCP client or static configuration with it, and one that appears, even
//! under a name seen before, is a new interface, configured as its name's configuration says
//! (DHCP without one).
//!
//! A configuration changed through the API is applied at once when its interface is present:
//! the current one is taken down (the DHCP client stopped and its lease's addresses and routes
//! removed, or the static addresses and routes removed), the new one brought up; if that fails,
//! the previous configuration and MTU are brought back. It is persisted once applied, and undone
//! the same way if it cannot be.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::link::LinkMessage;
use network_controller::DnsSettings;
use network_controller::InterfaceName;
use network_controller::InterfaceSettings;
use network_controller::Ipv4Method;
use network_controller::StaticIpv4;
use network_controller::network;

use crate::command::Command;
use crate::command::ConfigureError;
use crate::interface;
use crate::interface::DhcpOptions;
use crate::interface::DhcpTask;
use crate::link;
use crate::link::InterfaceAddress;
use crate::link::Link;
use crate::link::Netlink;
use crate::link_events::LinkEvent;
use crate::link_events::LinkState;
use crate::persisted_interfaces;
use crate::persisted_interfaces::Configurations;
use crate::shared::Shared;
use crate::static_addresses;

/// What a link event asks of the interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Configure this physical Ethernet link, not managed yet.
    Start(LinkState),
    /// Forget the managed interface of this index: it is gone.
    Stop(u32),
}

/// The interfaces network-controller configures, their configurations, and their DHCP clients.
pub struct Interfaces {
    shared: Arc<Shared>,
    /// `/sys/class/net`, which tells physical Ethernet links.
    sysfs_net: PathBuf,
    /// Where `configurations` are persisted.
    interfaces_file: PathBuf,
    /// The configurations set through the API, by name.
    configurations: Configurations,
    /// By interface index.
    managed: BTreeMap<u32, Managed>,
    /// Why the interfaces of these names could not be configured when they appeared or since;
    /// they are tried again on their next link event, or configuration.
    errors: BTreeMap<String, String>,
}

/// An interface network-controller configures.
struct Managed {
    link: LinkState,
    /// The configuration applied.
    settings: InterfaceSettings,
    /// The configuration's rank, kept from one configuration to the next, once it has one.
    rank: Option<u32>,
    mode: Mode,
}

/// How a managed interface is configured now.
enum Mode {
    Dhcp(DhcpTask),
    Static {
        rank: u32,
        addresses: StaticIpv4,
    },
    /// Set down: disabled, or its configuration could not be brought back.
    Down,
}

impl Interfaces {
    /// No interface yet; `sysfs_net` is `/sys/class/net`, `configurations` those persisted in
    /// `interfaces_file`.
    #[must_use]
    pub fn new(
        shared: Arc<Shared>,
        sysfs_net: PathBuf,
        interfaces_file: PathBuf,
        configurations: Configurations,
    ) -> Self {
        Self {
            shared,
            sysfs_net,
            interfaces_file,
            configurations,
            managed: BTreeMap::new(),
            errors: BTreeMap::new(),
        }
    }

    /// The changes `event` asks for. [`LinkEvent::Lost`] asks for none by itself: the links are
    /// to be listed again, for [`Self::reconcile`].
    #[must_use]
    pub fn changes(&self, event: &LinkEvent) -> Vec<Change> {
        match event {
            LinkEvent::Changed(link) if self.is_new_physical(link) => {
                vec![Change::Start(link.clone())]
            }
            LinkEvent::Removed(link) if self.managed.contains_key(&link.index) => {
                vec![Change::Stop(link.index)]
            }
            LinkEvent::Changed(_) | LinkEvent::Removed(_) | LinkEvent::Lost => Vec::new(),
        }
    }

    /// The changes that make the managed interfaces those of `links`, every link there is: the
    /// managed ones gone are stopped, the new physical Ethernet ones started.
    #[must_use]
    pub fn reconcile(&self, links: &[LinkState]) -> Vec<Change> {
        let gone = self
            .managed
            .keys()
            .filter(|index| !links.iter().any(|link| link.index == **index))
            .map(|&index| Change::Stop(index));
        let new = links
            .iter()
            .filter(|link| self.is_new_physical(link))
            .map(|link| Change::Start(link.clone()));
        gone.chain(new).collect()
    }

    /// Applies `changes`: configures the new interfaces, forgets those gone.
    pub async fn apply(&mut self, netlink: &Netlink, changes: Vec<Change>) {
        for change in changes {
            match change {
                Change::Start(link) => {
                    tracing::info!(interface = %link.name, index = link.index, "new interface");
                    self.start(netlink, link).await;
                }
                Change::Stop(index) => self.stop(index).await,
            }
        }
    }

    /// Answers `command`.
    pub async fn handle(&mut self, netlink: &Netlink, command: Command) {
        match command {
            Command::List(reply) => {
                let _ = reply.send(self.list(netlink).await);
            }
            Command::Configure {
                name,
                settings,
                reply,
            } => {
                let result = self.configure(netlink, name, settings).await;
                let _ = reply.send(result);
            }
        }
    }

    /// The configuration of the interface `name`.
    #[must_use]
    fn settings_of(&self, name: &str) -> InterfaceSettings {
        self.configurations.get(name).cloned().unwrap_or_default()
    }

    /// Configures `link`, which is not managed yet; a failure is logged and kept for the API.
    async fn start(&mut self, netlink: &Netlink, link: LinkState) {
        let settings = self.settings_of(&link.name);
        match self.bring_up(netlink, &link, &settings, None).await {
            Ok(mode) => {
                self.errors.remove(&link.name);
                self.insert(link, settings, None, mode);
            }
            Err(error) => {
                let error = format!("{error:#}");
                tracing::error!(interface = %link.name, error, "cannot configure the interface");
                self.shared
                    .set_interface_dns(link.index, DnsSettings::default());
                self.errors.insert(link.name, error);
            }
        }
    }

    /// Records `link` as managed, configured with `settings` in `mode`.
    fn insert(
        &mut self,
        link: LinkState,
        settings: InterfaceSettings,
        rank: Option<u32>,
        mode: Mode,
    ) {
        let rank = match &mode {
            Mode::Static { rank, .. } => Some(*rank),
            Mode::Dhcp(_) | Mode::Down => rank,
        };
        let index = link.index;
        let managed = Managed {
            link,
            settings,
            rank,
            mode,
        };
        // Only links not managed are inserted.
        self.managed.insert(index, managed);
    }

    /// Forgets the interface of `index`, its DHCP client stopped, its lease or static
    /// configuration with it; its addresses and routes went with the link.
    async fn stop(&mut self, index: u32) {
        let Some(Managed { link, mode, .. }) = self.managed.remove(&index) else {
            return;
        };
        tracing::warn!(interface = %link.name, index, "interface removed");
        // Once it returns, the client no longer updates the shared state: it is forgotten for
        // good.
        if let Mode::Dhcp(task) = mode
            && let Err(error) = task.abort().await
        {
            tracing::error!(interface = %link.name, %error, "DHCP task");
        }
        self.shared.remove_interface(index);
    }

    /// Brings `link` up as `settings` say, its routes of `rank` (the next free one if `None`):
    /// fully, or leaving it as it was but for its MTU and its being up.
    async fn bring_up(
        &self,
        netlink: &Netlink,
        link: &LinkState,
        settings: &InterfaceSettings,
        rank: Option<u32>,
    ) -> anyhow::Result<Mode> {
        self.shared
            .set_interface_dns(link.index, settings.dns().clone());
        if !settings.enabled() {
            netlink.set_down(&link.name).await?;
            tracing::info!(interface = %link.name, "interface disabled");
            return Ok(Mode::Down);
        }
        match settings.ipv4() {
            Ipv4Method::Dhcp => {
                let options = DhcpOptions {
                    rank,
                    mtu: settings.mtu(),
                };
                let task = interface::start(&self.shared, netlink, link, options).await?;
                self.shared.add_interface(link.index, &link.name);
                Ok(Mode::Dhcp(task))
            }
            Ipv4Method::Static(addresses) => {
                netlink.set_up(&link.name).await?;
                let configured = configured_link(link);
                if let Some(mtu) = settings.mtu() {
                    netlink.set_mtu(&configured, mtu.get()).await?;
                }
                let rank = rank.unwrap_or_else(|| self.shared.next_rank());
                let metric = interface::metric(rank);
                static_addresses::apply(netlink, &configured, addresses, metric).await?;
                tracing::info!(
                    interface = %link.name,
                    addresses = ?addresses
                        .addresses()
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    gateway = ?addresses.gateway(),
                    "configured statically"
                );
                self.shared
                    .bind_static(rank, link.index, &link.name, addresses.clone());
                Ok(Mode::Static {
                    rank,
                    addresses: addresses.clone(),
                })
            }
        }
    }

    /// Takes `managed`'s configuration down: its DHCP client stopped (which removes its lease's
    /// addresses and routes), or its static addresses and routes removed. Returns its rank.
    async fn tear_down(&self, netlink: &Netlink, managed: Managed) -> Option<u32> {
        let Managed {
            link, rank, mode, ..
        } = managed;
        match mode {
            Mode::Dhcp(task) => {
                let rank = match task.stop().await {
                    Ok(stopped) => stopped.or(rank),
                    Err(error) => {
                        tracing::error!(interface = %link.name, %error, "DHCP task");
                        rank
                    }
                };
                self.shared.remove_dhcp_interface(link.index);
                rank
            }
            Mode::Static { rank, addresses } => {
                let metric = interface::metric(rank);
                static_addresses::remove(netlink, &configured_link(&link), &addresses, metric)
                    .await;
                self.shared.unbind_static(rank);
                Some(rank)
            }
            Mode::Down => rank,
        }
    }

    /// Applies `settings` to the managed interface of `index`, or brings its previous
    /// configuration back.
    async fn reconfigure(
        &mut self,
        netlink: &Netlink,
        index: u32,
        settings: InterfaceSettings,
    ) -> anyhow::Result<()> {
        let Some(managed) = self.managed.remove(&index) else {
            return Ok(());
        };
        let link = managed.link.clone();
        let previous = managed.settings.clone();
        let mtu = netlink.mtu(&link.name).await.ok();
        let rank = self.tear_down(netlink, managed).await;
        let error = match self.bring_up(netlink, &link, &settings, rank).await {
            Ok(mode) => {
                self.errors.remove(&link.name);
                self.insert(link, settings, rank, mode);
                return Ok(());
            }
            Err(error) => error,
        };
        tracing::warn!(
            interface = %link.name,
            error = format!("{error:#}"),
            "cannot apply the configuration, restoring the previous one"
        );
        if let Some(mtu) = mtu.and_then(|mtu| u16::try_from(mtu).ok())
            && let Err(error) = netlink.set_mtu(&configured_link(&link), mtu).await
        {
            tracing::error!(
                interface = %link.name,
                error = format!("{error:#}"),
                "restoring the MTU"
            );
        }
        let mode = match self.bring_up(netlink, &link, &previous, rank).await {
            Ok(mode) => mode,
            Err(restoring) => {
                let restoring = format!("{restoring:#}");
                tracing::error!(
                    interface = %link.name,
                    error = restoring,
                    "cannot restore the previous configuration"
                );
                self.errors.insert(link.name.clone(), restoring);
                Mode::Down
            }
        };
        self.insert(link, previous, rank, mode);
        Err(error)
    }

    /// Applies `settings` (the default configuration when `None`) to the interface `name` if it
    /// is present, then persists it; answers the interface as it is then.
    async fn configure(
        &mut self,
        netlink: &Netlink,
        name: InterfaceName,
        settings: Option<InterfaceSettings>,
    ) -> Result<network::Interface, ConfigureError> {
        if self.sysfs_net.join(name.as_str()).exists()
            && !link::is_physical_ethernet(&self.sysfs_net, name.as_str())
        {
            return Err(ConfigureError::NotPhysical(name));
        }
        let new = settings.clone().unwrap_or_default();
        self.check_conflicts(netlink, &name, &new).await?;
        let previous = self.settings_of(name.as_str());
        let index = self.index_of(name.as_str());
        if let Some(index) = index {
            self.reconfigure(netlink, index, new)
                .await
                .map_err(ConfigureError::Applying)?;
        }
        let mut configurations = self.configurations.clone();
        match settings {
            Some(settings) => configurations.insert(name.clone(), settings),
            None => configurations.remove(&name),
        };
        if let Err(error) = persisted_interfaces::save(&self.interfaces_file, &configurations) {
            if let Some(index) = index
                && let Err(restoring) = self.reconfigure(netlink, index, previous).await
            {
                tracing::error!(
                    interface = %name,
                    error = format!("{restoring:#}"),
                    "cannot restore the previous configuration"
                );
            }
            return Err(ConfigureError::Persisting(error));
        }
        self.configurations = configurations;
        tracing::info!(interface = %name, "configuration kept");
        if index.is_none() {
            // Present but not configured (it failed to be): tried again with this one.
            self.errors.remove(name.as_str());
            if let Ok(links) = netlink.links().await
                && let Some(link) = links.into_iter().find(|link| link.name == name.as_str())
                && self.is_new_physical(&link)
            {
                self.start(netlink, link).await;
            }
        }
        let interfaces = self.list(netlink).await;
        Ok(interfaces
            .into_iter()
            .find(|interface| interface.name == name.as_str())
            .unwrap_or_else(|| network::Interface {
                name: name.to_string(),
                ..network::Interface::default()
            }))
    }

    /// The index of the managed interface `name`, if it is.
    #[must_use]
    fn index_of(&self, name: &str) -> Option<u32> {
        self.managed
            .iter()
            .find(|(_, managed)| managed.link.name == name)
            .map(|(index, _)| *index)
    }

    /// Fails if a static address of `settings` is another interface's: in its configuration, or
    /// on it now.
    async fn check_conflicts(
        &self,
        netlink: &Netlink,
        name: &InterfaceName,
        settings: &InterfaceSettings,
    ) -> Result<(), ConfigureError> {
        let Some(addresses) = settings.static_ipv4() else {
            return Ok(());
        };
        if let Some(conflict) = configured_elsewhere(&self.configurations, name, addresses) {
            return Err(ConfigureError::Conflict(conflict));
        }
        let own = self.index_of(name.as_str());
        let present = netlink
            .ipv4_addresses()
            .await
            .context("listing the addresses")
            .map_err(ConfigureError::Applying)?;
        for address in addresses.addresses() {
            if let Some(holder) = present
                .iter()
                .find(|other| other.address == address.address() && Some(other.index) != own)
            {
                let links = netlink.links().await.unwrap_or_default();
                let holder = (links.into_iter())
                    .find(|link| link.index == holder.index)
                    .map_or_else(|| format!("interface {}", holder.index), |link| link.name);
                return Err(ConfigureError::Conflict(format!(
                    "{} is already on {holder}",
                    address.address()
                )));
            }
        }
        Ok(())
    }

    /// The interfaces managed, configured or that failed to be, sorted by name, with what they
    /// have now.
    async fn list(&self, netlink: &Netlink) -> Vec<network::Interface> {
        let links = netlink.link_messages().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "listing the links");
            Vec::new()
        });
        let addresses = netlink.ipv4_addresses().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "listing the addresses");
            Vec::new()
        });
        let gateways = netlink.default_gateways().await.unwrap_or_else(|error| {
            tracing::warn!(%error, "listing the routes");
            Vec::new()
        });
        let managed = self
            .managed
            .values()
            .map(|managed| managed.link.name.as_str());
        let names: BTreeSet<&str> = managed
            .chain(self.configurations.keys().map(InterfaceName::as_str))
            .chain(self.errors.keys().map(String::as_str))
            .collect();
        names
            .into_iter()
            .map(|name| {
                let link = links
                    .iter()
                    .find(|msg| LinkState::from_message(msg).is_some_and(|link| link.name == name));
                network::Interface {
                    name: name.to_owned(),
                    config: Some(self.settings_of(name).into()),
                    configured: self.configurations.contains_key(name),
                    status: Some(self.status(name, link, &addresses, &gateways)),
                }
            })
            .collect()
    }

    /// What the interface `name`, described by `link` if present, has now.
    #[must_use]
    fn status(
        &self,
        name: &str,
        link: Option<&LinkMessage>,
        addresses: &[InterfaceAddress],
        gateways: &[(u32, Ipv4Addr)],
    ) -> network::InterfaceStatus {
        let error = self.errors.get(name).cloned();
        let Some(link) = link else {
            return network::InterfaceStatus {
                error,
                ..network::InterfaceStatus::default()
            };
        };
        let index = link.header.index;
        let (leased, name_servers) = self.shared.interface_status(index);
        network::InterfaceStatus {
            present: true,
            up: link.header.flags.contains(LinkFlags::Up),
            carrier: link.header.flags.contains(LinkFlags::LowerUp),
            mac: LinkState::from_message(link)
                .and_then(|state| state.mac)
                .map(|mac| format_mac(&mac)),
            mtu: link::mtu_of(link),
            addresses: addresses
                .iter()
                .filter(|address| address.index == index)
                .map(|address| network::Ipv4Address {
                    address: address.address.to_string(),
                    prefix_length: address.prefix_len.into(),
                })
                .collect(),
            gateway: gateways
                .iter()
                .find(|(oif, _)| *oif == index)
                .map(|(_, gateway)| gateway.to_string()),
            leased,
            name_servers: name_servers.iter().map(IpAddr::to_string).collect(),
            error,
        }
    }

    /// Whether `link` is a physical Ethernet link not managed yet.
    fn is_new_physical(&self, link: &LinkState) -> bool {
        !self.managed.contains_key(&link.index)
            && link::is_physical_ethernet(&self.sysfs_net, &link.name)
    }
}

/// `link`, as netlink's operations take it; static configurations need no Ethernet address.
#[must_use]
fn configured_link(link: &LinkState) -> Link {
    Link {
        name: link.name.clone(),
        index: link.index,
        mac: link.mac.unwrap_or_default(),
    }
}

/// Why `addresses` cannot be `name`'s, if another interface's configuration has one of them.
#[must_use]
fn configured_elsewhere(
    configurations: &Configurations,
    name: &InterfaceName,
    addresses: &StaticIpv4,
) -> Option<String> {
    for (other, configuration) in configurations {
        let Some(theirs) = configuration.static_ipv4().filter(|_| other != name) else {
            continue;
        };
        for address in addresses.addresses() {
            if theirs
                .addresses()
                .iter()
                .any(|their| their.address() == address.address())
            {
                return Some(format!("{} is configured on {other}", address.address()));
            }
        }
    }
    None
}

/// `mac` as `aa:bb:cc:dd:ee:ff`.
#[must_use]
fn format_mac(mac: &[u8; 6]) -> String {
    let bytes: Vec<String> = mac.iter().map(|byte| format!("{byte:02x}")).collect();
    bytes.join(":")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future;
    use std::path::Path;

    use tokio::sync::oneshot;

    use super::*;
    use crate::shared::tests::lease;
    use crate::shared::tests::shared;

    fn link(index: u32, name: &str) -> LinkState {
        LinkState {
            index,
            name: name.to_owned(),
            mac: Some([2, 0, 0, 0, 0, 1]),
            lower_up: true,
        }
    }

    /// `name` as a physical Ethernet interface of `sysfs_net`.
    fn physical(sysfs_net: &Path, name: &str) {
        fs::create_dir_all(sysfs_net.join(name).join("device")).unwrap();
        fs::write(sysfs_net.join(name).join("type"), "1\n").unwrap();
    }

    /// A DHCP client for `link` that binds a lease, then runs until aborted.
    fn dhcp(shared: &Arc<Shared>, link: &LinkState) -> DhcpTask {
        let shared = Arc::clone(shared);
        let (index, name) = (link.index, link.name.clone());
        let (stop, _) = oneshot::channel();
        DhcpTask::from_parts(
            tokio::spawn(async move {
                let rank = shared.next_rank();
                shared.bind(rank, index, &name, lease(&[[10, 0, 0, 2]], None, &[]));
                future::pending().await
            }),
            stop,
        )
    }

    /// Applies `changes` as [`Interfaces::apply`] does, with [`dhcp`] as the clients.
    async fn apply(interfaces: &mut Interfaces, changes: Vec<Change>) {
        for change in changes {
            match change {
                Change::Start(link) => {
                    let task = dhcp(&interfaces.shared, &link);
                    interfaces.shared.add_interface(link.index, &link.name);
                    let settings = InterfaceSettings::default();
                    interfaces.insert(link, settings, None, Mode::Dhcp(task));
                }
                Change::Stop(index) => interfaces.stop(index).await,
            }
        }
    }

    #[tokio::test]
    async fn removed_interfaces_stop_and_come_back() {
        let dir = tempfile::tempdir().unwrap();
        let sysfs_net = dir.path().join("sys/class/net");
        physical(&sysfs_net, "eth0");
        physical(&sysfs_net, "eth1");
        let shared = Arc::new(shared(dir.path()));
        let mut interfaces = Interfaces::new(
            Arc::clone(&shared),
            sysfs_net,
            dir.path().join("interfaces.json"),
            Configurations::new(),
        );
        let mut bound = shared.bound.subscribe();

        let eth0 = link(2, "eth0");
        let changes = interfaces.changes(&LinkEvent::Changed(eth0.clone()));
        assert_eq!(changes, [Change::Start(eth0.clone())]);
        apply(&mut interfaces, changes).await;
        let changes = interfaces.reconcile(&[link(1, "lo"), eth0.clone(), link(3, "eth1")]);
        assert_eq!(changes, [Change::Start(link(3, "eth1"))]);
        apply(&mut interfaces, changes).await;
        bound.wait_for(|&count| count == 2).await.unwrap();
        assert_eq!(shared.primary().as_deref(), Some("eth0"));
        assert!(
            interfaces
                .changes(&LinkEvent::Changed(eth0.clone()))
                .is_empty(),
            "already managed"
        );
        assert!(
            interfaces
                .changes(&LinkEvent::Changed(link(4, "veth0")))
                .is_empty(),
            "not physical"
        );

        // Deleted: its client stops, its lease is forgotten, eth1 becomes the primary.
        let changes = interfaces.changes(&LinkEvent::Removed(eth0.clone()));
        assert_eq!(changes, [Change::Stop(2)]);
        apply(&mut interfaces, changes).await;
        assert_eq!(*shared.bound.borrow(), 1);
        assert_eq!(shared.primary().as_deref(), Some("eth1"));
        assert!(
            interfaces
                .changes(&LinkEvent::Removed(eth0.clone()))
                .is_empty(),
            "no longer managed"
        );

        // Re-plugged with a new index: a new interface, which ranks after eth1.
        let replugged = link(5, "eth0");
        let changes = interfaces.changes(&LinkEvent::Changed(replugged.clone()));
        assert_eq!(changes, [Change::Start(replugged)]);
        apply(&mut interfaces, changes).await;
        bound.wait_for(|&count| count == 2).await.unwrap();
        assert_eq!(shared.primary().as_deref(), Some("eth1"));

        // Notifications lost meanwhile: eth1 went away, eth0 came back with the same index.
        let changes = interfaces.reconcile(&[link(1, "lo"), link(5, "eth0")]);
        assert_eq!(changes, [Change::Stop(3)]);
        apply(&mut interfaces, changes).await;
        assert_eq!(*shared.bound.borrow(), 1);
        assert_eq!(shared.primary().as_deref(), Some("eth0"));
        assert_eq!(interfaces.managed.keys().collect::<Vec<_>>(), [&5]);
    }

    #[test]
    fn finds_addresses_configured_elsewhere() {
        let settings = |address: &str| {
            let addresses = StaticIpv4::new(vec![address.parse().unwrap()], None).unwrap();
            InterfaceSettings::new(
                true,
                Ipv4Method::Static(addresses),
                DnsSettings::default(),
                None,
            )
            .unwrap()
        };
        let disabled = InterfaceSettings::new(
            false,
            settings("192.0.2.11/24").ipv4().clone(),
            DnsSettings::default(),
            None,
        )
        .unwrap();
        let configurations = Configurations::from([
            ("eth0".parse().unwrap(), settings("192.0.2.10/24")),
            ("eth2".parse().unwrap(), disabled),
        ]);
        let wanted = |address: &str| settings(address).static_ipv4().unwrap().clone();
        let eth0 = "eth0".parse().unwrap();
        let eth1 = "eth1".parse().unwrap();
        assert_eq!(
            configured_elsewhere(&configurations, &eth1, &wanted("192.0.2.10/25")).as_deref(),
            Some("192.0.2.10 is configured on eth0")
        );
        assert_eq!(
            configured_elsewhere(&configurations, &eth0, &wanted("192.0.2.10/24")),
            None,
            "its own"
        );
        assert_eq!(
            configured_elsewhere(&configurations, &eth1, &wanted("192.0.2.11/24")),
            None,
            "a disabled interface has no address"
        );
        assert_eq!(format_mac(&[2, 0, 0xab, 0, 0, 1]), "02:00:ab:00:00:01");
    }
}

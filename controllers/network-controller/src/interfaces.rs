//! The interfaces DHCP runs on, by index: a link that disappears takes its DHCP client and lease
//! with it, and one that appears, even under a name seen before, is a new interface.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use tokio::task::JoinHandle;

use crate::interface;
use crate::link;
use crate::link::Netlink;
use crate::link_events::LinkEvent;
use crate::link_events::LinkState;
use crate::shared::Shared;

/// What a link event asks of the interfaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Start DHCP on this physical Ethernet link, not managed yet.
    Start(LinkState),
    /// Stop DHCP on the managed interface of this index: it is gone.
    Stop(u32),
}

/// The interfaces DHCP runs on, and their tasks.
pub struct Interfaces {
    shared: Arc<Shared>,
    /// `/sys/class/net`, which tells physical Ethernet links.
    sysfs_net: PathBuf,
    /// By interface index.
    managed: BTreeMap<u32, Managed>,
}

/// An interface DHCP runs on.
struct Managed {
    name: String,
    task: JoinHandle<()>,
}

impl Interfaces {
    /// No interface yet; `sysfs_net` is `/sys/class/net`.
    #[must_use]
    pub fn new(shared: Arc<Shared>, sysfs_net: PathBuf) -> Self {
        Self {
            shared,
            sysfs_net,
            managed: BTreeMap::new(),
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

    /// Applies `changes`: starts DHCP on the new interfaces, stops it on those gone.
    pub async fn apply(&mut self, netlink: &Netlink, changes: Vec<Change>) {
        for change in changes {
            match change {
                Change::Start(link) => {
                    tracing::info!(interface = %link.name, index = link.index, "new interface");
                    if let Some(task) = interface::start(&self.shared, netlink, &link).await {
                        self.insert(&link, task);
                    }
                }
                Change::Stop(index) => self.stop(index).await,
            }
        }
    }

    /// Records `link` as managed by `task`, its DHCP client.
    fn insert(&mut self, link: &LinkState, task: JoinHandle<()>) {
        self.shared.add_interface(link.index, &link.name);
        let managed = Managed {
            name: link.name.clone(),
            task,
        };
        if let Some(replaced) = self.managed.insert(link.index, managed) {
            // Not reached: only links not managed are started.
            replaced.task.abort();
        }
    }

    /// Stops the DHCP client of the interface of `index` and forgets the interface and its lease;
    /// its addresses and routes went with the link.
    async fn stop(&mut self, index: u32) {
        let Some(Managed { name, task }) = self.managed.remove(&index) else {
            return;
        };
        tracing::warn!(interface = %name, index, "interface removed, DHCP stopped");
        task.abort();
        // Once it returns, the task no longer updates the shared state: it is forgotten for good.
        if let Err(error) = task.await
            && !error.is_cancelled()
        {
            tracing::error!(interface = %name, "DHCP task: {error}");
        }
        self.shared.remove_interface(index);
    }

    /// Whether `link` is a physical Ethernet link not managed yet.
    fn is_new_physical(&self, link: &LinkState) -> bool {
        !self.managed.contains_key(&link.index)
            && link::is_physical_ethernet(&self.sysfs_net, &link.name)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future;
    use std::path::Path;

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
    fn dhcp(shared: &Arc<Shared>, link: &LinkState) -> JoinHandle<()> {
        let shared = Arc::clone(shared);
        let (index, name) = (link.index, link.name.clone());
        tokio::spawn(async move {
            let rank = shared.next_rank();
            shared.bind(rank, index, &name, lease(&[[10, 0, 0, 2]], None, &[]));
            future::pending().await
        })
    }

    /// Applies `changes` as [`Interfaces::apply`] does, with [`dhcp`] as the clients.
    async fn apply(interfaces: &mut Interfaces, changes: Vec<Change>) {
        for change in changes {
            match change {
                Change::Start(link) => {
                    let task = dhcp(&interfaces.shared, &link);
                    interfaces.insert(&link, task);
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
        let mut interfaces = Interfaces::new(Arc::clone(&shared), sysfs_net);
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
        let task = interfaces.managed[&2].task.abort_handle();
        apply(&mut interfaces, changes).await;
        assert!(task.is_finished());
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
}

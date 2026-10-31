//! Delay locks on shutdown (`WatchShutdown`), like logind's: a reboot or power-off is announced
//! to their holders, which get until they release them, or their delay passes, to wind down
//! (kubelet stops its pods) before the services stop.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;

/// The longest a lock may delay a shutdown.
pub const MAX_DELAY: Duration = Duration::from_secs(600);

/// The locks held, and whether a shutdown was announced.
#[derive(Debug, Default)]
pub struct ShutdownLocks {
    state: watch::Sender<State>,
}

#[derive(Debug, Default)]
struct State {
    announced: bool,
    /// The delay of each lock held, by its id.
    held: BTreeMap<u64, Duration>,
    next: u64,
}

/// A lock, released when dropped.
#[derive(Debug)]
pub struct Lock {
    locks: Arc<ShutdownLocks>,
    id: u64,
}

impl ShutdownLocks {
    /// Takes a lock delaying a shutdown by `delay` at most ([`MAX_DELAY`] if longer).
    #[must_use]
    pub fn lock(self: &Arc<Self>, delay: Duration) -> Lock {
        let mut id = 0;
        self.state.send_modify(|state| {
            id = state.next;
            state.next += 1;
            state.held.insert(id, delay.min(MAX_DELAY));
        });
        Lock {
            locks: Arc::clone(self),
            id,
        }
    }

    /// Announces the shutdown to the holders: the longest delay of the locks held, `None` if
    /// there is none.
    #[must_use]
    pub fn announce(&self) -> Option<Duration> {
        let mut longest = None;
        self.state.send_modify(|state| {
            state.announced = true;
            longest = state.held.values().max().copied();
        });
        longest
    }

    /// Once no lock is held.
    pub async fn released(&self) {
        let mut state = self.state.subscribe();
        // The sender is `self`: it outlives the wait.
        let _ = state.wait_for(|state| state.held.is_empty()).await;
    }
}

impl Lock {
    /// Whether a shutdown was announced.
    #[must_use]
    pub fn announced(&self) -> bool {
        self.locks.state.borrow().announced
    }

    /// Once a shutdown is announced.
    pub async fn wait_announced(&self) {
        let mut state = self.locks.state.subscribe();
        let _ = state.wait_for(|state| state.announced).await;
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        self.locks.state.send_modify(|state| {
            state.held.remove(&self.id);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn the_longest_delay_until_every_lock_is_released() {
        let locks = Arc::new(ShutdownLocks::default());
        assert_eq!(locks.announce(), None, "no lock");

        let locks = Arc::new(ShutdownLocks::default());
        let short = locks.lock(Duration::from_secs(5));
        let long = locks.lock(Duration::from_secs(3600));
        assert!(!short.announced());
        assert_eq!(locks.announce(), Some(MAX_DELAY), "capped");
        short.wait_announced().await;
        assert!(long.announced());

        let released = tokio::spawn({
            let locks = Arc::clone(&locks);
            async move { locks.released().await }
        });
        drop(short);
        tokio::task::yield_now().await;
        assert!(!released.is_finished(), "one lock is still held");
        drop(long);
        tokio::time::timeout(Duration::from_secs(5), released)
            .await
            .unwrap()
            .unwrap();
    }
}

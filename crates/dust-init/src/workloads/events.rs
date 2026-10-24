//! Container exits, from CRI's `GetContainerEvents` stream.
//!
//! One subscription serves every supervisor: containerd's event queue blocks on slow
//! subscribers, so the stream is drained promptly into a broadcast channel. When the stream is
//! unavailable, supervisors fall back to polling the container status.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use cri_api::v1::ContainerEventType;
use tokio::sync::broadcast;
use tonic::Code;

use super::cri::{ContainerId, Cri};

/// Pending events per subscriber; a supervisor lagging behind re-checks its container.
const CAPACITY: usize = 64;
const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(1);
/// How often a container's status is polled while events are not streamed.
pub const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// How often it is still checked while they are, in case an event is lost.
pub const SAFETY_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
enum Event {
    Stopped(ContainerId),
    /// Events may have been missed: every subscriber re-checks its container.
    Resync,
}

/// The shared exit notifications.
#[derive(Clone)]
pub struct Exits {
    events: broadcast::Sender<Event>,
    live: Arc<AtomicBool>,
}

impl Exits {
    /// Starts following the runtime's events.
    pub fn spawn(cri: Cri) -> Self {
        let exits = Self::detached();
        tokio::spawn(exits.clone().follow(cri));
        exits
    }

    /// Notifications without a source: subscribers only poll.
    fn detached() -> Self {
        Self {
            events: broadcast::channel(CAPACITY).0,
            live: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn subscribe(&self) -> Subscription {
        Subscription {
            events: self.events.subscribe(),
            live: self.live.clone(),
        }
    }

    async fn follow(self, cri: Cri) {
        let mut warned = false;
        loop {
            match cri.container_events().await {
                Ok(mut stream) => {
                    self.live.store(true, Ordering::SeqCst);
                    // Exits during the gap went unseen.
                    let _ = self.events.send(Event::Resync);
                    tracing::debug!("following container events");
                    loop {
                        match stream.message().await {
                            Ok(Some(event)) => {
                                if event.container_event_type == ContainerEventType::ContainerStoppedEvent as i32 {
                                    let _ = self.events.send(Event::Stopped(ContainerId::from(event.container_id)));
                                }
                            }
                            Ok(None) => break,
                            Err(status) => {
                                tracing::debug!("container events stream ended: {status}");
                                break;
                            }
                        }
                    }
                    self.live.store(false, Ordering::SeqCst);
                }
                Err(status) if status.code() == Code::Unimplemented => {
                    tracing::warn!("the runtime does not stream container events, polling container statuses");
                    return;
                }
                Err(status) if !warned => {
                    warned = true;
                    tracing::warn!("cannot follow container events, polling container statuses: {status}");
                }
                Err(status) => tracing::debug!("cannot follow container events: {status}"),
            }
            tokio::time::sleep(RESUBSCRIBE_DELAY).await;
        }
    }
}

/// A supervisor's view of the exit notifications, subscribed before its container starts so no
/// exit is missed.
pub struct Subscription {
    events: broadcast::Receiver<Event>,
    live: Arc<AtomicBool>,
}

impl Subscription {
    /// Whether exits are being streamed (otherwise statuses must be polled).
    pub fn live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    /// Resolves when container `id` may have changed state: an event names it, or events may
    /// have been missed.
    pub async fn changed(&mut self, id: &ContainerId) {
        loop {
            match self.events.recv().await {
                Ok(Event::Stopped(stopped)) if stopped == *id => return,
                Ok(Event::Stopped(_)) => {}
                Ok(Event::Resync) | Err(broadcast::error::RecvError::Lagged(_)) => return,
                // No more events: polling takes over.
                Err(broadcast::error::RecvError::Closed) => std::future::pending().await,
            }
        }
    }

    /// How long to wait for an event before checking the container's status anyway.
    pub fn poll_interval(&self) -> Duration {
        if self.live() { SAFETY_INTERVAL } else { POLL_INTERVAL }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notifies_the_matching_container_only() {
        let exits = Exits::detached();
        let mut subscription = exits.subscribe();
        assert!(!subscription.live());
        assert_eq!(subscription.poll_interval(), POLL_INTERVAL);

        let mine = ContainerId::from("mine".to_owned());
        exits
            .events
            .send(Event::Stopped(ContainerId::from("other".to_owned())))
            .unwrap();
        exits.events.send(Event::Stopped(mine.clone())).unwrap();
        tokio::time::timeout(Duration::from_secs(1), subscription.changed(&mine))
            .await
            .unwrap();

        exits
            .events
            .send(Event::Stopped(ContainerId::from("other".to_owned())))
            .unwrap();
        let pending = tokio::time::timeout(Duration::from_millis(50), subscription.changed(&mine)).await;
        assert!(pending.is_err());

        exits.events.send(Event::Resync).unwrap();
        tokio::time::timeout(Duration::from_secs(1), subscription.changed(&mine))
            .await
            .unwrap();

        exits.live.store(true, Ordering::SeqCst);
        assert_eq!(subscription.poll_interval(), SAFETY_INTERVAL);
    }
}

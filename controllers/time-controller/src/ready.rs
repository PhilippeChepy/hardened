//! time-controller's readiness, reported to serviced (`READY=1`).

use std::time::Duration;

use libserviced::notify;
use tokio::time::Instant;

/// How long the services after time-controller wait for the clock once it is configured:
/// unreachable servers must not hold them.
pub const READY_TIMEOUT: Duration = Duration::from_secs(30);

/// The readiness serviced waits for: reported after the first correction, or at the deadline
/// without one.
pub struct Ready {
    /// `None` once reported.
    deadline: Option<Instant>,
}

impl Ready {
    /// Not ready before `deadline`, unless the clock gets synchronized.
    #[must_use]
    pub fn new(deadline: Instant) -> Self {
        Self {
            deadline: Some(deadline),
        }
    }

    /// Reports the readiness if the clock is `in_sync`, or once past the deadline.
    pub fn update(&mut self, in_sync: bool) {
        if !self.due(in_sync) {
            return;
        }
        // Tried again at the next update if it fails.
        if let Err(error) = notify::ready() {
            tracing::warn!(%error, "cannot notify serviced of the readiness");
            return;
        }
        self.deadline = None;
        if in_sync {
            tracing::info!("ready");
        } else {
            tracing::warn!("ready, without a correction within {READY_TIMEOUT:?}");
        }
    }

    /// Whether the readiness is to be reported now.
    #[must_use]
    fn due(&self, in_sync: bool) -> bool {
        self.deadline
            .is_some_and(|deadline| in_sync || Instant::now() >= deadline)
    }

    /// The deadline, until the readiness is reported.
    #[must_use]
    pub fn pending(&self) -> Option<Instant> {
        self.deadline
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Without NOTIFY_SOCKET (no test sets it), reporting sends nothing and succeeds.
    #[tokio::test]
    async fn ready_once_in_sync_or_at_the_deadline() {
        let mut ready = Ready::new(Instant::now() + Duration::from_secs(60));
        assert!(!ready.due(/* in_sync */ false));
        ready.update(/* in_sync */ false);
        assert!(ready.pending().is_some());
        assert!(ready.due(/* in_sync */ true));
        ready.update(/* in_sync */ true);
        assert_eq!(ready.pending(), None);
        assert!(!ready.due(/* in_sync */ true), "reported once");

        let mut ready = Ready::new(Instant::now());
        assert!(ready.due(/* in_sync */ false), "past the deadline");
        ready.update(/* in_sync */ false);
        assert_eq!(ready.pending(), None);
    }
}

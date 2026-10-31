//! The polling loop: a round every poll interval with the configured servers, restarted at
//! every new configuration.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use libserviced::notify;
use time_controller::TimeSource;
use tokio::time::Instant;

use crate::client::Client;
use crate::measurement::Measurement;
use crate::ptp;
use crate::ptp::PtpClock;
use crate::ready::READY_TIMEOUT;
use crate::ready::Ready;
use crate::time_service::TimeService;

/// Polls with the configuration of `service`, once there is one, and records each round in it.
/// Reports the readiness once the clock is synchronized, or [`READY_TIMEOUT`] after the first
/// configuration.
pub async fn poll(service: Arc<TimeService>) -> Infallible {
    let mut configs = service.configs.subscribe();
    let mut ready = None;
    let mut status_text = String::new();
    'configs: loop {
        let config = match configs.wait_for(Option::is_some).await {
            Ok(config) => config.clone(),
            Err(_) => None,
        };
        let Some(config) = config else {
            // The service keeps the sender for as long as it runs: this does not happen.
            tracing::error!("the configuration's sender is gone, polling stops");
            return std::future::pending().await;
        };
        let ptp = match config.source {
            TimeSource::Ntp => None,
            TimeSource::Auto | TimeSource::Ptp => match PtpClock::find() {
                Ok(ptp) => ptp,
                Err(error) => {
                    tracing::warn!(%error, "cannot open the PTP clock");
                    None
                }
            },
        };
        tracing::info!(
            source = ?config.source,
            ptp = ptp.as_ref().map(|ptp| ptp.device.display().to_string()),
            servers = ?config.servers,
            origin = ?config.origin,
            "polling"
        );
        let ready = ready.get_or_insert_with(|| Ready::new(Instant::now() + READY_TIMEOUT));
        let mut sources = Sources {
            source: config.source,
            ptp,
            ntp: Client::new(config.servers),
            synchronized: false,
        };
        loop {
            let (round, poll) = sources.round().await;
            let in_sync = round.is_ok();
            report_status(&round, &mut status_text);
            service.record(round, 1 << poll);
            ready.update(in_sync);
            let next = Instant::now() + Duration::from_secs(1 << poll);
            loop {
                let wake = ready.pending().map_or(next, |deadline| deadline.min(next));
                tokio::select! {
                    () = tokio::time::sleep_until(wake) => {}
                    changed = configs.changed() => {
                        if changed.is_err() {
                            tracing::error!("the configuration's sender is gone, polling stops");
                            return std::future::pending().await;
                        }
                        continue 'configs;
                    }
                }
                ready.update(in_sync);
                if Instant::now() >= next {
                    break;
                }
            }
        }
    }
}

/// What the clock is synchronized with, as configured.
struct Sources {
    source: TimeSource,
    /// The hypervisor's PTP clock, if any and not `ntp`.
    ptp: Option<PtpClock>,
    ntp: Client,
    /// Whether the last round corrected the clock.
    synchronized: bool,
}

impl Sources {
    /// A round with the PTP clock or the NTP servers, as configured: the correction or why there
    /// is none, and the poll interval after it (a power of two seconds).
    async fn round(&mut self) -> (Result<Measurement, String>, u32) {
        let ptp = match (&self.ptp, self.source) {
            (Some(ptp), _) => Some(ptp.round(self.synchronized)),
            (None, TimeSource::Ptp) => Some(Err(
                "no KVM PTP clock (settings.hardened.time.source is ptp)".to_owned(),
            )),
            (None, _) => None,
        };
        let round = match (ptp, self.source) {
            (Some(Ok(measurement)), _) => (Ok(measurement), ptp::POLL),
            (Some(Err(error)), TimeSource::Ptp) => (Err(error), ptp::POLL),
            (Some(Err(error)), _) => {
                tracing::warn!(%error, "the PTP clock failed, falling back to NTP");
                (self.ntp.round().await, self.ntp.poll)
            }
            (None, _) => (self.ntp.round().await, self.ntp.poll),
        };
        self.synchronized = round.0.is_ok();
        round
    }
}

/// Sets the service's status text to what the clock is synchronized with after `round`, when
/// it changes from `sent`.
fn report_status(round: &Result<Measurement, String>, sent: &mut String) {
    let text = match round {
        Ok(correction) => format!("synchronized with {}", correction.source),
        Err(_) => "not synchronized".to_owned(),
    };
    if text != *sent {
        // Informational only: a failure is not worth more than a debug line.
        if let Err(error) = notify::status(&text) {
            tracing::debug!(%error, "cannot send the status text to serviced");
        }
        *sent = text;
    }
}

#[cfg(test)]
mod tests {
    use controllers_helpers::NonEmpty;
    use time_controller::TimeConfig;
    use time_controller::TimeOrigin;
    use time_controller::TimeSource;

    use super::*;

    #[tokio::test]
    async fn polls_once_configured() {
        let dir = tempfile::tempdir().unwrap();
        let service = Arc::new(TimeService::new(dir.path().join("state.json"), None));
        let mut statuses = service.status.subscribe();
        tokio::spawn(poll(Arc::clone(&service)));
        let polled = tokio::time::timeout(Duration::from_millis(200), statuses.changed()).await;
        assert!(polled.is_err(), "no round before the configuration");

        // Nothing answers NTP on the loopback: the query fails at once.
        let config = TimeConfig {
            servers: NonEmpty::new("127.0.0.1".parse().unwrap()),
            origin: TimeOrigin::Settings,
            source: TimeSource::Auto,
        };
        service.apply(config).unwrap();
        tokio::time::timeout(Duration::from_secs(10), statuses.changed())
            .await
            .expect("a round")
            .unwrap();
        let status = statuses.borrow().clone();
        assert_eq!(status.poll_seconds, 32);
        assert!(status.error.unwrap().contains("127.0.0.1"));
        assert_eq!(status.last, None);
    }
}

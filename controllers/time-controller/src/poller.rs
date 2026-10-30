//! The polling loop: a round every poll interval with the configured servers, restarted at
//! every new configuration.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use libserviced::notify;
use tokio::time::Instant;

use crate::client::Client;
use crate::measurement::Measurement;
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
        let config = configs
            .wait_for(Option::is_some)
            .await
            .expect("the service keeps the sender")
            .clone()
            .expect("waited for a configuration");
        tracing::info!(servers = ?config.servers, origin = ?config.origin, "polling");
        let ready = ready.get_or_insert_with(|| Ready::new(Instant::now() + READY_TIMEOUT));
        let mut client = Client::new(config.servers);
        loop {
            let round = client.round().await;
            let in_sync = round.is_ok();
            report_status(&round, &mut status_text);
            service.record(round, 1 << client.poll);
            ready.update(in_sync);
            let next = Instant::now() + Duration::from_secs(1 << client.poll);
            loop {
                let wake = ready.pending().map_or(next, |deadline| deadline.min(next));
                tokio::select! {
                    () = tokio::time::sleep_until(wake) => {}
                    changed = configs.changed() => {
                        changed.expect("the service keeps the sender");
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

/// Sets the service's status text to what the clock is synchronized with after `round`, when
/// it changes from `sent`.
fn report_status(round: &Result<Measurement, String>, sent: &mut String) {
    let text = match round {
        Ok(correction) => format!("synchronized with {}", correction.server),
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

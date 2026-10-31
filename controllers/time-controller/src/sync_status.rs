//! What the client last did, served with the kernel clock's state and the configuration as
//! `hardened.time.v1.Status`.

use time_controller::TimeConfig;
use time_controller::TimeServer;
use time_controller::time;

use crate::measurement::Measurement;

/// What the client last did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncStatus {
    /// The measurement of the last correction, if any.
    pub last: Option<Measurement>,
    /// Why the last round corrected nothing, if it did not.
    pub error: Option<String>,
    /// Seconds between rounds; 0 before the first.
    pub poll_seconds: u32,
}

impl SyncStatus {
    /// The API's view of this status, with the servers of `config` (none before the first
    /// configuration) and the kernel's `clock`.
    #[must_use]
    pub fn to_message(&self, config: Option<&TimeConfig>, clock: time::Clock) -> time::Status {
        let (servers, origin, source) = match config {
            Some(config) => (
                config.servers.iter().map(TimeServer::to_string).collect(),
                time::Origin::from(config.origin),
                time::Source::from(config.source),
            ),
            None => (Vec::new(), time::Origin::Unspecified, time::Source::Auto),
        };
        time::Status {
            clock: Some(clock),
            servers,
            origin: origin.into(),
            last_correction: self.last.as_ref().map(time::Correction::from),
            error: self.error.clone(),
            poll_interval_seconds: self.poll_seconds,
            source: source.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use controllers_helpers::NonEmpty;
    use time_controller::TimeOrigin;
    use time_controller::TimeSource;

    use super::*;
    use crate::measurement::tests::measurement;

    #[test]
    fn converts_to_the_message() {
        let clock = time::Clock {
            synchronized: true,
            estimated_error_us: 400,
            max_error_us: 1500,
            frequency_ppm: -1.5,
        };
        let config = TimeConfig {
            servers: NonEmpty::from_vec(vec![
                "time.example.com".parse().unwrap(),
                "192.0.2.123".parse().unwrap(),
            ])
            .unwrap(),
            origin: TimeOrigin::Dhcp,
            source: TimeSource::Auto,
        };
        let status = SyncStatus {
            last: Some(measurement()),
            error: None,
            poll_seconds: 64,
        };
        let message = status.to_message(Some(&config), clock);
        assert_eq!(message.clock, Some(clock));
        assert_eq!(message.servers, ["time.example.com", "192.0.2.123"]);
        assert_eq!(message.origin(), time::Origin::Dhcp);
        assert_eq!(
            message.last_correction,
            Some(time::Correction::from(&measurement()))
        );
        assert_eq!(message.error, None);
        assert_eq!(message.poll_interval_seconds, 64);

        let unconfigured = SyncStatus::default().to_message(None, clock);
        assert!(unconfigured.servers.is_empty());
        assert_eq!(unconfigured.origin(), time::Origin::Unspecified);
        assert_eq!(unconfigured.last_correction, None);
    }
}

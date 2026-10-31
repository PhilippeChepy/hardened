//! A correction of the clock, served as `hardened.time.v1.Correction`.

use std::net::SocketAddr;

use time_controller::TimeServer;
use time_controller::time;

use crate::packet::Nanos;

/// A correction of the clock, and the reply it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    /// The server, as configured (a host name or an address).
    pub server: TimeServer,
    /// The address of the server that replied.
    pub address: SocketAddr,
    /// The server's stratum.
    pub stratum: u8,
    /// The server's reference: its clock's code at stratum 1, the address of its own server
    /// above.
    pub reference: String,
    /// What the clock was corrected by, in nanoseconds (positive: it was behind).
    pub offset_ns: Nanos,
    /// The round trip to the server, less its processing time, in nanoseconds.
    pub delay_ns: Nanos,
    /// Whether the clock was stepped rather than slewed.
    pub stepped: bool,
    /// When, in nanoseconds since the Unix epoch, after the correction.
    pub at_unix_ns: Nanos,
}

impl From<&Measurement> for time::Correction {
    fn from(measurement: &Measurement) -> Self {
        const NANOS_PER_SECOND: Nanos = 1_000_000_000;

        let corrected_at = prost_types::Timestamp {
            seconds: measurement.at_unix_ns.div_euclid(NANOS_PER_SECOND),
            // Below 10^9: it fits in an i32, never saturates.
            nanos: i32::try_from(measurement.at_unix_ns.rem_euclid(NANOS_PER_SECOND))
                .unwrap_or(i32::MAX),
        };
        Self {
            server: measurement.server.to_string(),
            address: measurement.address.to_string(),
            stratum: measurement.stratum.into(),
            reference: measurement.reference.clone(),
            offset_ns: measurement.offset_ns,
            delay_ns: measurement.delay_ns,
            stepped: measurement.stepped,
            corrected_at: Some(corrected_at),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn measurement() -> Measurement {
        Measurement {
            server: "time.example.com".parse().unwrap(),
            address: "192.0.2.123:123".parse().unwrap(),
            stratum: 2,
            reference: "192.0.2.1".into(),
            offset_ns: -1_500_000,
            delay_ns: 800_000,
            stepped: false,
            at_unix_ns: 1_700_000_000_250_000_000,
        }
    }

    #[test]
    fn converts_to_the_message() {
        let correction = time::Correction::from(&measurement());
        assert_eq!(
            correction,
            time::Correction {
                server: "time.example.com".into(),
                address: "192.0.2.123:123".into(),
                stratum: 2,
                reference: "192.0.2.1".into(),
                offset_ns: -1_500_000,
                delay_ns: 800_000,
                stepped: false,
                corrected_at: Some(prost_types::Timestamp {
                    seconds: 1_700_000_000,
                    nanos: 250_000_000,
                }),
            }
        );
    }
}

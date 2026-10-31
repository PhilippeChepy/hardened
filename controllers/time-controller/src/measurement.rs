//! A correction of the clock, served as `hardened.time.v1.Correction`.

use std::fmt;
use std::net::SocketAddr;

use time_controller::TimeServer;
use time_controller::time;

use crate::packet::Nanos;

/// A correction of the clock, and what it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Measurement {
    pub source: Source,
    /// What the clock was corrected by, in nanoseconds (positive: it was behind).
    pub offset_ns: Nanos,
    /// The measurement's delay, in nanoseconds: the round trip to the server less its processing
    /// time, or the time the system clock took to read the PTP clock.
    pub delay_ns: Nanos,
    /// Whether the clock was stepped rather than slewed.
    pub stepped: bool,
    /// When, in nanoseconds since the Unix epoch, after the correction.
    pub at_unix_ns: Nanos,
}

/// What a correction came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Source {
    /// An NTP reply.
    Ntp {
        /// The server, as configured (a host name or an address).
        server: TimeServer,
        /// The address of the server that replied.
        address: SocketAddr,
        /// The server's stratum.
        stratum: u8,
        /// The server's reference: its clock's code at stratum 1, the address of its own server
        /// above.
        reference: String,
    },
    /// The hypervisor's PTP clock.
    Ptp {
        /// Its device.
        device: String,
        /// The name its driver gives it.
        name: String,
    },
}

impl fmt::Display for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ntp { server, .. } => write!(f, "{server}"),
            Self::Ptp { device, name } => write!(f, "{name} ({device})"),
        }
    }
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
        let source = match &measurement.source {
            Source::Ntp {
                server,
                address,
                stratum,
                reference,
            } => time::correction::Source::Ntp(time::NtpReply {
                server: server.to_string(),
                address: address.to_string(),
                stratum: (*stratum).into(),
                reference: reference.clone(),
            }),
            Source::Ptp { device, name } => time::correction::Source::Ptp(time::PtpClock {
                device: device.clone(),
                name: name.clone(),
            }),
        };
        Self {
            source: Some(source),
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
            source: Source::Ntp {
                server: "time.example.com".parse().unwrap(),
                address: "192.0.2.123:123".parse().unwrap(),
                stratum: 2,
                reference: "192.0.2.1".into(),
            },
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
                source: Some(time::correction::Source::Ntp(time::NtpReply {
                    server: "time.example.com".into(),
                    address: "192.0.2.123:123".into(),
                    stratum: 2,
                    reference: "192.0.2.1".into(),
                })),
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

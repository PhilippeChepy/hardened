//! dust-ntp: an SNTP client keeping the clock in sync, run by dust-init in a sandbox where it
//! keeps only `CAP_SYS_TIME`.
//!
//! Every poll interval, it resolves its servers, queries each address, and corrects the clock
//! with the reply closest to its reference clock ([`clock`]). It writes its [`Status`] to a file
//! dust-init serves through the API.

pub mod clock;
pub mod packet;

use std::io;
use std::path::Path;

use serde::{Deserialize, Serialize};

/// What the client last did, for the API.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    /// The servers it queries, in order.
    pub servers: Vec<String>,
    /// The measurement of the last correction, if any.
    pub last: Option<Measurement>,
    /// Why the last round corrected nothing, if it did not.
    pub error: Option<String>,
    /// Seconds between rounds.
    pub poll_seconds: u32,
}

/// A correction of the clock, and the reply it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Measurement {
    pub server: String,
    pub address: String,
    pub stratum: u8,
    /// The server's reference: its clock's code at stratum 1, the address of its own server
    /// above.
    pub reference: String,
    /// What the clock was corrected by, in nanoseconds (positive: it was behind).
    pub offset_ns: i64,
    pub delay_ns: i64,
    /// Whether the clock was stepped rather than slewed.
    pub stepped: bool,
    /// When, in nanoseconds since the Unix epoch, after the correction.
    pub at_unix_ns: i64,
}

impl Status {
    /// Writes the status to `path`, through a temporary file renamed over it, so a reader never
    /// sees a partial status.
    pub fn write(&self, path: &Path) -> io::Result<()> {
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, serde_json::to_vec(self)?)?;
        std::fs::rename(&temporary, path)
    }

    pub fn read(path: &Path) -> io::Result<Self> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_round_trips_through_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("status.json");
        let status = Status {
            servers: vec!["pool.ntp.org".into()],
            last: Some(Measurement {
                server: "pool.ntp.org".into(),
                address: "192.0.2.1:123".into(),
                stratum: 2,
                reference: "192.0.2.10".into(),
                offset_ns: -1_500_000,
                delay_ns: 12_000_000,
                stepped: false,
                at_unix_ns: 1_767_225_600_000_000_000,
            }),
            error: None,
            poll_seconds: 64,
        };
        status.write(&path).unwrap();
        assert_eq!(Status::read(&path).unwrap(), status);
        assert!(!path.with_extension("tmp").exists());
    }
}

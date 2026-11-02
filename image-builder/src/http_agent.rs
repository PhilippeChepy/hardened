//! The HTTP client of downloads: timeouts, so that a stalled server (ftp.gnu.org has stalls of
//! many minutes) fails a download rather than hanging the build.

use std::sync::OnceLock;
use std::time::Duration;

/// How long connecting may take.
const CONNECT: Duration = Duration::from_secs(30);
/// How long a read may wait for data: longer is a stall.
const READ: Duration = Duration::from_secs(60);

/// The agent of every download.
pub fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        ureq::Agent::config_builder()
            .timeout_connect(Some(CONNECT))
            .timeout_per_read(Some(READ))
            .user_agent("hardened-image-builder")
            .build()
            .into()
    })
}

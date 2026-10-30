//! What [`run`](crate::run::run) configures, and where it keeps its files.

use std::path::PathBuf;
use std::time::Duration;

/// The configuration of [`run`](crate::run::run); the default is the production one.
#[derive(Debug)]
pub struct Options {
    /// `resolv.conf`, in the directory `/etc/resolv.conf` links to.
    pub resolv_conf: PathBuf,
    /// Where the DNS override is kept across restarts.
    pub state_file: PathBuf,
    /// `/sys/class/net`: DHCP runs on its physical Ethernet interfaces, including ones appearing
    /// later.
    pub sysfs_net: PathBuf,
    /// Bound on the wait for a first interface to show up.
    pub link_timeout: Duration,
    /// Bound on the wait for a first lease.
    pub lease_timeout: Duration,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            resolv_conf: "/run/hardened/resolv.conf".into(),
            state_file: "/run/network-controller/state.json".into(),
            sysfs_net: "/sys/class/net".into(),
            link_timeout: Duration::from_secs(10),
            lease_timeout: Duration::from_secs(30),
        }
    }
}

//! dust-ntp, the SNTP client, run in a [`sandbox`](crate::sandbox) that keeps `CAP_SYS_TIME`.
//!
//! It parses network input and sets the clock, which anyone answering its unauthenticated
//! queries can steer anyway; it sees only the resolver configuration and its status directory.

use std::net::Ipv4Addr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use rustix::process::{Gid, Uid};
use rustix::thread::CapabilitySet;
use tracing::info;

use crate::process::Reaper;
use crate::sandbox::{Bind, Limits, Spec, Supervisor, Syscalls};
use crate::settings::NtpSettings;

/// uid/gid dust-ntp runs as: not `nobody` (dust-api's), which the control socket admits.
const ID: u32 = 65533;
const STATE_DIR: &str = "/run/dust-ntp";
const STATUS: &str = "/run/dust-ntp/status.json";
/// The servers when neither user-data nor DHCP gives any.
const DEFAULT_SERVER: &str = "pool.ntp.org";
const LIMITS: Limits = Limits {
    memory_bytes: 32 << 20,
    tasks: 4,
    cpu_percent: 10,
};
/// Resolving names (musl's resolver), querying servers, writing the status and adjusting the
/// clock, on top of [`BASE_SYSCALLS`](crate::sandbox::BASE_SYSCALLS).
const SYSCALLS: Syscalls = Syscalls {
    allowed: &[
        42,  // connect
        44,  // sendto
        45,  // recvfrom
        46,  // sendmsg
        47,  // recvmsg
        49,  // bind
        51,  // getsockname
        54,  // setsockopt
        55,  // getsockopt
        82,  // rename
        159, // adjtimex
        305, // clock_adjtime
    ],
    restricted: &[
        // socket: AF_INET, AF_INET6 only.
        (41, 0, &[2, 10]),
    ],
};

/// Where the servers come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    Settings,
    Dhcp,
    Default,
}

/// The servers dust-ntp queries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Servers {
    pub names: Vec<String>,
    pub origin: Origin,
}

impl Servers {
    /// `settings.ntp.time-servers`, else the servers of DHCP, else [`DEFAULT_SERVER`].
    pub fn choose(settings: &NtpSettings, dhcp: &[Ipv4Addr]) -> Self {
        if !settings.time_servers.is_empty() {
            Self {
                names: settings.time_servers.iter().map(ToString::to_string).collect(),
                origin: Origin::Settings,
            }
        } else if !dhcp.is_empty() {
            Self {
                names: dhcp.iter().map(ToString::to_string).collect(),
                origin: Origin::Dhcp,
            }
        } else {
            Self {
                names: vec![DEFAULT_SERVER.to_owned()],
                origin: Origin::Default,
            }
        }
    }
}

/// The supervised dust-ntp.
pub struct Ntp(Supervisor);

impl Ntp {
    pub fn start(reaper: Reaper, servers: &Servers) -> anyhow::Result<Self> {
        let dir = Path::new(STATE_DIR);
        std::fs::create_dir_all(dir).context(STATE_DIR)?;
        rustix::fs::chown(dir, Some(Uid::from_raw(ID)), Some(Gid::from_raw(ID))).context(STATE_DIR)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755)).context(STATE_DIR)?;

        let mut args = Vec::new();
        for server in &servers.names {
            args.extend(["--server".to_owned(), server.clone()]);
        }
        args.extend(["--status".to_owned(), STATUS.to_owned()]);
        let spec = Spec {
            name: "dust-ntp",
            program: "/usr/bin/dust-ntp",
            args,
            env: vec![("RUST_LOG", "info".into())],
            id: ID,
            binds: vec![
                // resolv.conf and hosts, links into /run/hardened.
                Bind {
                    path: "/etc",
                    exec: false,
                    writable: false,
                },
                Bind {
                    path: crate::net::RUNTIME_DIR,
                    exec: false,
                    writable: false,
                },
                Bind {
                    path: STATE_DIR,
                    exec: false,
                    writable: true,
                },
            ],
            capabilities: CapabilitySet::SYS_TIME,
            limits: LIMITS,
            syscalls: SYSCALLS,
        };
        let supervisor = Supervisor::start(reaper, spec)?;
        info!(servers = ?servers.names, origin = ?servers.origin, "time synchronization enabled");
        Ok(Self(supervisor))
    }

    pub async fn stop(self) {
        self.0.stop().await;
    }
}

/// What dust-ntp last did; `None` before its first round.
pub fn status() -> std::io::Result<Option<dust_ntp::Status>> {
    match dust_ntp::Status::read(Path::new(STATUS)) {
        Ok(status) => Ok(Some(status)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_then_dhcp_then_the_default() {
        let dhcp = [Ipv4Addr::new(10, 0, 0, 4)];
        let configured = NtpSettings {
            time_servers: vec!["time.example.com".parse().unwrap()],
        };
        assert_eq!(
            Servers::choose(&configured, &dhcp),
            Servers {
                names: vec!["time.example.com".into()],
                origin: Origin::Settings
            }
        );
        assert_eq!(
            Servers::choose(&NtpSettings::default(), &dhcp),
            Servers {
                names: vec!["10.0.0.4".into()],
                origin: Origin::Dhcp
            }
        );
        assert_eq!(Servers::choose(&NtpSettings::default(), &[]).origin, Origin::Default);
    }
}

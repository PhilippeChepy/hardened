//! Who calls serviced's API, sends to a notify socket, or is named to `IdentifyProcess`: the
//! service whose cgroup the process is in. Each service's processes run in its own cgroup,
//! `/sandbox/<service>` or `/services/<service>` ([`sandbox`](crate::sandbox)), which they cannot
//! leave (a sandbox does not see the cgroup filesystem; an unconfined service is trusted). A
//! process in a cgroup below it is the service's too.

use std::fmt::{self, Display, Formatter};
use std::sync::Arc;

use libserviced::definition::ServiceName;
use tokio::net::UnixStream;

use crate::sandbox;

/// Finds the service of a process, by its pid. Tests make their own.
pub type Resolver = Arc<dyn Fn(u32) -> Option<ServiceName> + Send + Sync>;

/// The resolver of the machine: the process's cgroup, from `/proc/<pid>/cgroup`.
#[must_use]
pub fn resolver() -> Resolver {
    Arc::new(|pid| {
        let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
        service_of_cgroup(&cgroup)
    })
}

/// The service of a process whose `/proc/<pid>/cgroup` is `contents` (cgroup v2: `0::<path>`).
#[must_use]
fn service_of_cgroup(contents: &str) -> Option<ServiceName> {
    let path = contents.lines().find_map(|line| line.strip_prefix("0::"))?;
    let mut components = path.strip_prefix('/')?.split('/');
    let parent = components.next()?;
    if parent != sandbox::SANDBOX_CGROUPS && parent != sandbox::UNCONFINED_CGROUPS {
        return None;
    }
    components.next()?.parse().ok()
}

/// The process at the other end of a connection to serviced's API, as it connected.
#[derive(Debug, Clone)]
pub enum Caller {
    /// Its credentials are unknown.
    Unknown,
    Process {
        pid: u32,
        /// The service it belongs to; `None` for any other process, refused.
        service: Option<ServiceName>,
    },
}

impl Caller {
    /// The peer of `stream`, found by its credentials (`SO_PEERCRED`) and `resolve`.
    #[must_use]
    pub fn of(stream: &UnixStream, resolve: &Resolver) -> Self {
        let pid = stream
            .peer_cred()
            .ok()
            .and_then(|credentials| credentials.pid())
            .and_then(|pid| u32::try_from(pid).ok());
        match pid {
            Some(pid) => Self::Process {
                pid,
                service: resolve(pid),
            },
            None => Self::Unknown,
        }
    }

    /// The service it belongs to, if any.
    #[must_use]
    pub fn service(&self) -> Option<&ServiceName> {
        match self {
            Self::Process { service, .. } => service.as_ref(),
            Self::Unknown => None,
        }
    }
}

impl Display for Caller {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Process {
                pid,
                service: Some(service),
            } => write!(f, "{service} (pid {pid})"),
            Self::Process { pid, service: None } => write!(f, "pid {pid}, of no service"),
            Self::Unknown => f.write_str("unknown process"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service(contents: &str) -> Option<String> {
        service_of_cgroup(contents).map(|name| name.to_string())
    }

    #[test]
    fn services_by_cgroup() {
        assert_eq!(
            service("0::/sandbox/machine-apiproxy\n").as_deref(),
            Some("machine-apiproxy")
        );
        assert_eq!(
            service("0::/services/machine-controller\n").as_deref(),
            Some("machine-controller")
        );
        assert_eq!(
            service("0::/services/kubelet/child\n").as_deref(),
            Some("kubelet"),
            "below the service's cgroup"
        );
        assert_eq!(
            service("1:name=systemd:/x\n0::/sandbox/time-controller\n").as_deref(),
            Some("time-controller"),
            "the v2 line"
        );
        for other in [
            "0::/\n",
            "0::/sandbox\n",
            "0::/services/\n",
            "0::/services\n",
            "0::/other/kubelet\n",
            "0::/k8s.io/abc\n",
            "0::/system.slice/services/x\n",
            "0::/services/Not-A-Service\n",
            "",
        ] {
            assert_eq!(service(other), None, "{other:?}");
        }
    }
}

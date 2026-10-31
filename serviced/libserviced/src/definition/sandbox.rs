//! The confinement of a service's processes, as its service file declares it.

use std::num::NonZeroU32;
use std::ops::{Deref, Not};

use serde::{Deserialize, Serialize};

use crate::definition::{AbsolutePath, Capability, Error, Syscall};

/// The confinement of every process of a service: its own namespaces but the network's, a root
/// holding only its program and `binds`, and a seccomp allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Sandbox {
    /// uid and gid, without supplementary groups.
    pub user: u32,
    /// Kept through the `exec`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<Capability>,
    /// Host paths visible at the same path.
    #[serde(default, skip_serializing_if = "<[Bind]>::is_empty")]
    pub binds: Binds,
    /// System calls allowed on top of serviced's base set.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub syscalls: Vec<Syscall>,
    /// The socket families `socket` may create.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub socket_families: Vec<SocketFamily>,
    /// The `ioctl` requests allowed on top of the few every program makes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ioctls: Vec<Ioctl>,
    /// The resources of its cgroup.
    pub limits: Limits,
}

/// A sandbox's binds, none under another: each path is bound once, with its own flags.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<Bind>", into = "Vec<Bind>")]
pub struct Binds(Vec<Bind>);

impl TryFrom<Vec<Bind>> for Binds {
    type Error = Error;

    fn try_from(binds: Vec<Bind>) -> Result<Self, Error> {
        for (i, a) in binds.iter().enumerate() {
            for b in &binds[i + 1..] {
                if a.path.starts_with(&b.path) || b.path.starts_with(&a.path) {
                    return Err(Error::Invalid(format!(
                        "nested binds {} and {}",
                        a.path, b.path
                    )));
                }
            }
        }
        Ok(Self(binds))
    }
}

impl From<Binds> for Vec<Bind> {
    fn from(binds: Binds) -> Self {
        binds.0
    }
}

impl Deref for Binds {
    type Target = [Bind];

    fn deref(&self) -> &[Bind] {
        &self.0
    }
}

/// A host path visible in the sandbox, read-only, without executables or devices unless
/// allowed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Bind {
    /// The same on the host and in the sandbox.
    pub path: AbsolutePath,
    /// The sandbox may write under it.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub writable: bool,
    /// Files under it may be executed.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub exec: bool,
    /// Device nodes under it may be opened (`/dev/tpmrm0`).
    #[serde(default, skip_serializing_if = "Not::not")]
    pub device: bool,
    /// Left out when the path does not exist when the service starts, rather than failing it.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub optional: bool,
}

/// A socket family (`AF_*`) the sandbox may create sockets of.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs, reason = "self-explanatory variants")]
pub enum SocketFamily {
    Unix,
    Inet,
    Inet6,
    Netlink,
    Packet,
}

impl SocketFamily {
    /// The family's number on Linux (`AF_UNIX` is 1).
    #[must_use]
    pub fn number(self) -> u64 {
        match self {
            Self::Unix => 1,
            Self::Inet => 2,
            Self::Inet6 => 10,
            Self::Netlink => 16,
            Self::Packet => 17,
        }
    }
}

/// An `ioctl` request a sandbox may make, named as in Linux's headers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[allow(missing_docs, reason = "self-explanatory variants")]
pub enum Ioctl {
    PtpSysOffset,
}

impl Ioctl {
    /// The request's number on x86-64 (`PTP_SYS_OFFSET` is `_IOW('=', 5, struct
    /// ptp_sys_offset)`).
    #[must_use]
    pub fn number(self) -> u64 {
        match self {
            Self::PtpSysOffset => 0x4340_3d05,
        }
    }
}

/// The resources a sandbox's cgroup caps; none can be zero, which would keep the service from
/// running at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Limits {
    /// Memory (`memory.max`), in MiB.
    pub memory_mib: NonZeroU32,
    /// Processes and threads (`pids.max`).
    pub tasks: NonZeroU32,
    /// CPU time (`cpu.max`), in thousandths of one CPU.
    pub cpu_millicores: NonZeroU32,
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIMITS: &str = "limits.memory-mib = 1\nlimits.tasks = 1\nlimits.cpu-millicores = 1\n";

    fn parse(text: &str) -> Result<Sandbox, toml::de::Error> {
        toml::from_str(&format!("user = 1\n{text}"))
    }

    #[test]
    fn sandboxes_resolve_names_and_round_trip() {
        let text = format!(
            "{LIMITS}capabilities = [\"SYS_TIME\"]\nsyscalls = [\"clock_adjtime\"]\n\
             [[binds]]\npath = \"/run/a\"\n[[binds]]\npath = \"/run/ab\"\n"
        );
        let sandbox = parse(&text).unwrap();
        assert_eq!(sandbox.capabilities[0].number(), 25);
        assert_eq!(sandbox.syscalls[0].number(), 305);
        assert_eq!(sandbox.binds.len(), 2, "/run/ab is not under /run/a");
        let back: Sandbox = toml::from_str(&toml::to_string(&sandbox).unwrap()).unwrap();
        assert_eq!(back, sandbox);
    }

    #[test]
    fn invalid_sandboxes_are_rejected() {
        for (bad, why) in [
            ("syscalls = [\"nope\"]", "unknown system call"),
            (
                "capabilities = [\"CAP_SYS_TIME\"]",
                "unknown variant `CAP_SYS_TIME`",
            ),
            ("[[binds]]\npath = \"run\"", "absolute path"),
            (
                "[[binds]]\npath = \"/run\"\n[[binds]]\npath = \"/run/a\"",
                "nested binds",
            ),
            ("unknown = 1", "unknown field"),
        ] {
            let error = parse(&format!("{LIMITS}{bad}\n")).unwrap_err().to_string();
            assert!(error.contains(why), "{bad}: {error}");
        }
        for zero in ["memory-mib", "tasks", "cpu-millicores"] {
            let limits = LIMITS.replace(&format!("{zero} = 1"), &format!("{zero} = 0"));
            assert!(parse(&limits).is_err(), "{zero} = 0 accepted");
        }
    }
}

//! The services a policy may allow by name, and their ports.

use std::fmt;
use std::num::NonZeroU16;
use std::str::FromStr;

use crate::ports::Port;
use crate::ports::Ports;
use crate::ports::Protocol;

/// A service known by name: its ports.
#[derive(Debug, PartialEq, Eq)]
pub struct ServiceInfo {
    /// `ssh`.
    pub name: &'static str,
    /// What it is, for people.
    pub description: &'static str,
    /// Its ports, at least one.
    pub ports: &'static [Ports],
}

/// `port` of TCP, at compile time.
const fn tcp(port: u16) -> Ports {
    Ports::one(Protocol::Tcp, port_number(port))
}

/// `port` of UDP, at compile time.
const fn udp(port: u16) -> Ports {
    Ports::one(Protocol::Udp, port_number(port))
}

/// `first` to `last` of `protocol`, at compile time.
const fn range(protocol: Protocol, first: u16, last: u16) -> Ports {
    assert!(first <= last);
    Ports::from_parts(protocol, port_number(first), port_number(last))
}

const fn port_number(port: u16) -> Port {
    match NonZeroU16::new(port) {
        Some(port) => Port::new(port),
        None => panic!("port 0"),
    }
}

/// The services, by name.
pub static SERVICES: &[ServiceInfo] = &[
    ServiceInfo {
        name: "ssh",
        description: "Secure Shell (remote login)",
        ports: &[tcp(22)],
    },
    ServiceInfo {
        name: "http",
        description: "Web server",
        ports: &[tcp(80)],
    },
    ServiceInfo {
        name: "https",
        description: "Secure web server",
        ports: &[tcp(443), udp(443)],
    },
    ServiceInfo {
        name: "http-alt",
        description: "Web server on port 8080 (development)",
        ports: &[tcp(8080)],
    },
    ServiceInfo {
        name: "dns",
        description: "Domain name server",
        ports: &[tcp(53), udp(53)],
    },
    ServiceInfo {
        name: "llmnr",
        description: "Local name resolution (LLMNR)",
        ports: &[tcp(5355), udp(5355)],
    },
    ServiceInfo {
        name: "ssdp",
        description: "UPnP device discovery (SSDP)",
        ports: &[udp(1900)],
    },
    ServiceInfo {
        name: "ntp",
        description: "Time server (NTP)",
        ports: &[udp(123)],
    },
    ServiceInfo {
        name: "ipp",
        description: "Printer sharing (IPP)",
        ports: &[tcp(631)],
    },
    ServiceInfo {
        name: "smb",
        description: "Windows file sharing (SMB)",
        ports: &[tcp(139), tcp(445)],
    },
    ServiceInfo {
        name: "rdp",
        description: "Remote desktop (RDP)",
        ports: &[tcp(3389)],
    },
    ServiceInfo {
        name: "vnc",
        description: "Remote desktop (VNC)",
        ports: &[tcp(5900)],
    },
    ServiceInfo {
        name: "kdeconnect",
        description: "KDE Connect and GSConnect (phone integration)",
        ports: &[
            range(Protocol::Tcp, 1714, 1764),
            range(Protocol::Udp, 1714, 1764),
        ],
    },
    ServiceInfo {
        name: "syncthing",
        description: "Syncthing (file synchronization)",
        ports: &[tcp(22000), udp(22000), udp(21027)],
    },
    ServiceInfo {
        name: "wireguard",
        description: "WireGuard VPN",
        ports: &[udp(51820)],
    },
];

/// A service of [`SERVICES`], by name.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Service(&'static ServiceInfo);

impl Service {
    /// What it is and its ports.
    #[must_use]
    pub fn info(self) -> &'static ServiceInfo {
        self.0
    }

    /// Its name.
    #[must_use]
    pub fn name(self) -> &'static str {
        self.0.name
    }

    /// Every service, in [`SERVICES`]' order.
    pub fn all() -> impl Iterator<Item = Self> {
        SERVICES.iter().map(Self)
    }
}

impl fmt::Debug for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Service({})", self.0.name)
    }
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.name)
    }
}

/// A name that is not a service's.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0:?} is not a known service")]
pub struct UnknownService(pub String);

impl FromStr for Service {
    type Err = UnknownService;

    fn from_str(name: &str) -> Result<Self, UnknownService> {
        SERVICES
            .iter()
            .find(|service| service.name == name)
            .map(Self)
            .ok_or_else(|| UnknownService(name.to_owned()))
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    #[test]
    fn names_round_trip() {
        for service in Service::all() {
            assert_eq!(service.to_string().parse::<Service>().unwrap(), service);
            assert!(!service.info().ports.is_empty(), "{service}");
        }
        assert_eq!("ssh".parse::<Service>().unwrap().info().ports, [tcp(22)]);
        assert!("SSH".parse::<Service>().is_err());
        assert!("22/tcp".parse::<Service>().is_err());
    }

    #[test]
    fn names_are_unique_and_not_ports() {
        let names: HashSet<_> = SERVICES.iter().map(|service| service.name).collect();
        assert_eq!(names.len(), SERVICES.len());
        for name in names {
            assert!(
                name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-'),
                "{name}"
            );
        }
    }
}

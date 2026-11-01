//! A service file: what serviced runs, what it waits for, and how it is confined.

use std::collections::BTreeMap;
use std::ops::Not;

use serde::{Deserialize, Serialize};
use toml::Table;

use crate::definition::{AbsolutePath, Command, Sandbox, ServiceName, SocketName};

/// A service file, its layers merged.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Service {
    /// For humans; serviced does not use it.
    #[serde(default)]
    pub description: String,
    /// A disabled service is not started; a later layer enables it.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The sockets serviced listens on for it, passed to `exec`. A sandbox gets what serving
    /// them and identifying callers needs. With an activating one, the service starts on
    /// activation rather than at boot ([`Service::socket_activated`]).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sockets: Vec<Socket>,
    /// The program and its arguments.
    pub exec: Command,
    /// Run to completion, in order, before `exec`; the service fails if one fails.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec_pre: Vec<Command>,
    /// Run after `exec` exits, whatever the reason.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec_post: Vec<Command>,
    /// Run once the service's process is gone, when it is stopped: how it undoes what it did. At
    /// shutdown, they run once every other process is gone, the last started service first.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec_stop: Vec<Command>,
    /// When to run `exec` again after it exits.
    #[serde(default)]
    pub restart: Restart,
    /// Services that must be ready first. If one fails, is disabled or does not exist, this one
    /// does not start.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub requires: Vec<ServiceName>,
    /// What must hold for the service to start.
    #[serde(default, skip_serializing_if = "Condition::is_empty")]
    pub condition: Condition,
    /// Ready once it sent `READY=1` on `NOTIFY_SOCKET`, rather than once started.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub notify: bool,
    /// A job rather than a daemon: ready once `exec` exited successfully, and staying so, never
    /// restarted then (`restart` applies to its failures). What requires it starts after it,
    /// and its `exec-stop` runs at shutdown.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub oneshot: bool,
    /// The environment, the only one the program gets.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<String, String>,
    /// Created before the service starts, owned by the sandbox's user, and kept across restarts.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub runtime_directories: Vec<AbsolutePath>,
    /// Copy the program's output to the console, besides its log.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub console: bool,
    /// What the service may do through serviced's API, besides `IdentifyProcess`, open to all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub api: Vec<Access>,
    /// Confinement; without it, the program runs as root, in the host's namespaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<Sandbox>,
    /// Ignored by serviced: data of whoever wrote the file.
    #[serde(default, skip_serializing_if = "Table::is_empty")]
    pub meta: Table,
}

fn yes() -> bool {
    true
}

impl Service {
    /// Whether the service starts on activation rather than at boot: on the first connection to
    /// one of its activating sockets, or when a service requiring it starts.
    #[must_use]
    pub fn socket_activated(&self) -> bool {
        self.sockets.iter().any(|socket| socket.activate)
    }
}

/// When `exec` runs again after it exits.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[allow(missing_docs, reason = "self-explanatory variants")]
pub enum Restart {
    #[default]
    Always,
    OnFailure,
    Never,
}

/// What must hold for a service to start.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Condition {
    /// The service is skipped unless this path exists when it would start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path_exists: Option<AbsolutePath>,
}

impl Condition {
    fn is_empty(&self) -> bool {
        self.path_exists.is_none()
    }
}

/// A grant of serviced's API to a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Access {
    /// Services and logs.
    Read,
    /// Starting, stopping and restarting services, reloading the service files, and power.
    Control,
}

/// A unix stream socket serviced listens on while the service is enabled and its condition
/// holds, passed to `exec` as systemd does: connections made before it runs wait in the backlog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Socket {
    /// Its name in `LISTEN_FDNAMES`, which also names its `SERVICED_ALLOW_<NAME>` variable.
    pub name: SocketName,
    /// Where it is created.
    pub path: AbsolutePath,
    /// The services that may connect; the service refuses the others.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow: Vec<ServiceName>,
    /// A connection to it starts the service, which then does not start at boot.
    #[serde(default, skip_serializing_if = "Not::not")]
    pub activate: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_services_are_rejected() {
        for (bad, why) in [
            ("exec = []", "without a program"),
            ("exec = [\"x\"]", "absolute path"),
            ("exec = [\"/x\"]\nexec-pre = [[\"-x\"]]", "absolute path"),
            ("exec = [\"/x\", \"a\\u0000b\"]", "NUL byte"),
            (
                "exec = [\"/x\"]\nruntime-directories = [\"run/x\"]",
                "absolute path",
            ),
            (
                "exec = [\"/x\"]\ncondition.path-exists = \"x\"",
                "absolute path",
            ),
            (
                "exec = [\"/x\"]\n[[sockets]]\nname = \"API\"\npath = \"/run/x.sock\"",
                "invalid socket name",
            ),
            (
                "exec = [\"/x\"]\n[[sockets]]\nname = \"api\"\npath = \"x.sock\"",
                "absolute path",
            ),
        ] {
            let error = toml::from_str::<Service>(bad).unwrap_err().to_string();
            assert!(error.contains(why), "{bad}: {error}");
        }
    }

    #[test]
    fn services_round_trip() {
        let text = r#"
exec = ["/usr/bin/x", "--flag"]
exec-post = [["-/usr/bin/ctr", "rm"]]
runtime-directories = ["/run/x"]
condition.path-exists = "/dev/tpmrm0"

[[sockets]]
name = "api"
path = "/run/x/api.sock"
allow = ["machine-controller"]
activate = true
"#;
        let service: Service = toml::from_str(text).unwrap();
        assert!(service.socket_activated());
        let back: Service = toml::from_str(&toml::to_string(&service).unwrap()).unwrap();
        assert_eq!(back, service);
    }
}

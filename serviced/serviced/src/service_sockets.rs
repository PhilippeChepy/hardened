//! The sockets serviced listens on for a service (its `[[sockets]]`), from boot or from when it
//! is enabled, until it is disabled, removed or redefined. serviced never accepts on them: it
//! passes them to the service's `exec` ([`listen_exec`](crate::listen_exec)), and, for a
//! socket-activated service that is not running, watches them for a connection
//! ([`activation_watch`](crate::activation_watch)). Connections made meanwhile wait in the
//! backlog.

use std::io;
use std::io::ErrorKind;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use libserviced::definition::{AbsolutePath, Service, ServiceName, Socket};

use crate::mounts;

/// A socket's mode: anyone who sees it may connect. Services authorize their callers themselves,
/// with serviced's `IdentifyProcess`.
const SOCKET_MODE: u32 = 0o666;

/// A listening socket of a service.
#[derive(Debug, Clone)]
pub struct Listener {
    /// As the service file defines it.
    pub socket: Socket,
    /// Shared with the runs it is passed to.
    pub fd: Arc<OwnedFd>,
}

/// The listening sockets of a service, removed when dropped.
#[derive(Debug)]
pub struct ServiceSockets {
    listeners: Vec<Listener>,
}

impl ServiceSockets {
    /// Binds the sockets of `service`. A socket's directory is created if missing: root's, mode
    /// 0755, unless it is one of the service's runtime directories, created as its run will
    /// (its sandbox user's), so the service's own files can go next to the socket.
    pub fn bind(service: &Service) -> anyhow::Result<Self> {
        let owner = service.sandbox.as_ref().map_or(0, |sandbox| sandbox.user);
        let mut sockets = Self {
            listeners: Vec::with_capacity(service.sockets.len()),
        };
        for socket in &service.sockets {
            let parent = socket.path.parent().unwrap_or(Path::new("/"));
            if service
                .runtime_directories
                .iter()
                .any(|dir| dir.as_path() == parent)
            {
                mounts::create_dir(parent, owner, 0o755)?;
            } else {
                mounts::create_root_dir(parent)
                    .with_context(|| format!("creating {}", parent.display()))?;
            }
            let fd = listen(&socket.path)
                .with_context(|| format!("socket {}: {}", socket.name, socket.path.display()))?;
            // Pushed at once: dropping `sockets` on a later failure removes it.
            sockets.listeners.push(Listener {
                socket: socket.clone(),
                fd: Arc::new(OwnedFd::from(fd)),
            });
        }
        Ok(sockets)
    }

    /// Whether these are the sockets `service` defines.
    #[must_use]
    pub fn match_definition(&self, service: &Service) -> bool {
        self.listeners
            .iter()
            .map(|listener| &listener.socket)
            .eq(&service.sockets)
    }

    /// The sockets, in the order of the service file.
    #[must_use]
    pub fn listeners(&self) -> &[Listener] {
        &self.listeners
    }
}

impl Drop for ServiceSockets {
    fn drop(&mut self) {
        for listener in &self.listeners {
            let _ = std::fs::remove_file(&listener.socket.path);
        }
    }
}

/// The paths of the sockets, among those of `services`, whose `allow` names `caller`.
#[must_use]
pub fn allowed_sockets<'a>(
    caller: &ServiceName,
    services: impl IntoIterator<Item = &'a Service>,
) -> Vec<AbsolutePath> {
    services
        .into_iter()
        .flat_map(|service| &service.sockets)
        .filter(|socket| socket.allow.contains(caller))
        .map(|socket| socket.path.clone())
        .collect()
}

/// Listens on a unix stream socket at `path` (a stale one is replaced), mode [`SOCKET_MODE`]:
/// a service's, or serviced's own.
pub fn listen(path: &Path) -> io::Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt as _;

    match std::fs::remove_file(path) {
        Err(e) if e.kind() != ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
    Ok(listener)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    use std::os::unix::net::UnixStream;
    use std::path::PathBuf;

    use super::*;

    fn service(text: &str) -> Service {
        toml::from_str(text).unwrap()
    }

    #[test]
    fn sockets_are_created_listening_and_removed() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let definition = service(&format!(
            r#"
exec = ["/usr/bin/x"]
[[sockets]]
name = "api"
path = "{root}/api.sock"
allow = ["machine-controller"]
[[sockets]]
name = "admin"
path = "{root}/new/deeper/admin.sock"
"#
        ));
        std::fs::write(dir.path().join("api.sock"), "stale").unwrap();

        let sockets = ServiceSockets::bind(&definition).unwrap();
        assert!(sockets.match_definition(&definition));
        let names: Vec<&str> = sockets
            .listeners()
            .iter()
            .map(|listener| listener.socket.name.as_str())
            .collect();
        assert_eq!(names, ["api", "admin"]);
        for path in ["api.sock", "new/deeper/admin.sock"] {
            let path = dir.path().join(path);
            let metadata = std::fs::metadata(&path).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o666, "{}", path.display());
            UnixStream::connect(&path).expect("listening");
        }
        for created in ["new", "new/deeper"] {
            let metadata = std::fs::metadata(dir.path().join(created)).unwrap();
            assert_eq!(metadata.mode() & 0o7777, 0o755, "{created}");
        }

        let changed = service(&format!(
            "exec = [\"/usr/bin/x\"]\n[[sockets]]\nname = \"api\"\npath = \"{root}/api.sock\"\n"
        ));
        assert!(!sockets.match_definition(&changed), "allow changed");
        drop(sockets);
        assert!(!dir.path().join("api.sock").exists());
        assert!(!dir.path().join("new/deeper/admin.sock").exists());
    }

    #[test]
    fn sockets_go_in_the_runtime_directory() {
        let me = rustix::process::getuid().as_raw();
        if rustix::process::getgid().as_raw() != me {
            // The directory gets the sandbox user as its uid and gid, which needs both to be the
            // test user's, or root.
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_str().unwrap();
        let definition = service(&format!(
            r#"
exec = ["/usr/bin/x"]
runtime-directories = ["{root}/own"]
[[sockets]]
name = "api"
path = "{root}/own/api.sock"
[sandbox]
user = {me}
limits.memory-mib = 1
limits.tasks = 1
limits.cpu-millicores = 1
"#
        ));
        let own = dir.path().join("own");
        std::fs::create_dir(&own).unwrap();
        std::fs::set_permissions(&own, std::fs::Permissions::from_mode(0o700)).unwrap();
        let _sockets = ServiceSockets::bind(&definition).unwrap();
        let metadata = std::fs::metadata(&own).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o755, "made as its run will");
        assert_eq!(metadata.uid(), me);
        assert!(own.join("api.sock").exists());
    }

    #[test]
    fn allowed_sockets_by_caller() {
        let services = [
            service(
                r#"
exec = ["/usr/bin/a"]
[[sockets]]
name = "api"
path = "/run/a/api.sock"
allow = ["machine-apiproxy", "machine-controller"]
[[sockets]]
name = "admin"
path = "/run/a/admin.sock"
allow = ["machine-controller"]
"#,
            ),
            service(
                r#"
exec = ["/usr/bin/b"]
[[sockets]]
name = "api"
path = "/run/b/api.sock"
allow = ["machine-apiproxy"]
"#,
            ),
        ];
        let allowed = |caller: &str| -> Vec<PathBuf> {
            allowed_sockets(&caller.parse().unwrap(), &services)
                .into_iter()
                .map(PathBuf::from)
                .collect()
        };
        assert_eq!(
            allowed("machine-apiproxy"),
            [
                PathBuf::from("/run/a/api.sock"),
                PathBuf::from("/run/b/api.sock")
            ]
        );
        assert_eq!(
            allowed("machine-controller"),
            [
                PathBuf::from("/run/a/api.sock"),
                PathBuf::from("/run/a/admin.sock")
            ]
        );
        assert!(allowed("web").is_empty());
    }
}

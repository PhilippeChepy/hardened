//! dust-api, the remote mTLS front of the control API, run in a [`sandbox`](crate::sandbox).
//!
//! It is the only process parsing network input before authentication, so it sees only the
//! control socket and its TLS material, and may only add networking to the base system calls.

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use rustix::process::{Gid, Uid};
use rustix::thread::CapabilitySet;
use tracing::info;

use crate::process::Reaper;
use crate::sandbox::{Bind, Limits, Spec, Supervisor, Syscalls};
use crate::settings::ApiConfig;

/// uid/gid dust-api runs as (`nobody`), which the control socket admits.
pub const ID: u32 = 65534;
const TLS_DIR: &str = "/run/dust-api/tls";
/// Enough for an admin API; a flood hits these limits instead of the machine.
const LIMITS: Limits = Limits {
    memory_bytes: 128 << 20,
    tasks: 128,
    cpu_percent: 50,
};
/// Listening, accepting and the unix socket to dust-init, on top of
/// [`BASE_SYSCALLS`](crate::sandbox::BASE_SYSCALLS).
const SYSCALLS: Syscalls = Syscalls {
    allowed: &[
        42,  // connect
        43,  // accept
        44,  // sendto
        45,  // recvfrom
        46,  // sendmsg
        47,  // recvmsg
        48,  // shutdown
        49,  // bind
        50,  // listen
        51,  // getsockname
        52,  // getpeername
        54,  // setsockopt
        55,  // getsockopt
        288, // accept4
    ],
    restricted: &[
        // socket, socketpair: AF_UNIX, AF_INET, AF_INET6 only.
        (41, 0, &[1, 2, 10]),
        (53, 0, &[1]),
    ],
};

/// The supervised dust-api.
pub struct Api(Supervisor);

impl Api {
    /// Writes the TLS material and starts dust-api in its sandbox.
    pub fn start(reaper: Reaper, api: &ApiConfig) -> anyhow::Result<Self> {
        write_tls(api).context("writing the TLS material")?;
        let spec = Spec {
            name: "dust-api",
            program: "/usr/bin/dust-api",
            args: vec![
                "--listen".into(),
                api.listen.to_string(),
                "--socket".into(),
                dust_proto::CONTROL_SOCKET.into(),
                "--tls-dir".into(),
                TLS_DIR.into(),
            ],
            env: vec![("RUST_LOG", "info".into())],
            id: ID,
            binds: vec![
                Bind {
                    path: control_socket_dir(),
                    exec: false,
                    writable: false,
                },
                Bind {
                    path: TLS_DIR,
                    exec: false,
                    writable: false,
                },
            ],
            capabilities: CapabilitySet::empty(),
            limits: LIMITS,
            syscalls: SYSCALLS,
        };
        let supervisor = Supervisor::start(reaper, spec)?;
        info!(listen = %api.listen, "API enabled");
        Ok(Self(supervisor))
    }

    /// Stops dust-api.
    pub async fn stop(self) {
        self.0.stop().await;
    }
}

/// The directory of the control socket, bound rather than the socket itself so dust-init can
/// recreate it.
fn control_socket_dir() -> &'static str {
    let socket = dust_proto::CONTROL_SOCKET;
    socket.rsplit_once('/').map_or(socket, |(dir, _)| dir)
}

fn write_tls(api: &ApiConfig) -> anyhow::Result<()> {
    let dir = Path::new(TLS_DIR);
    std::fs::create_dir_all(dir)?;
    let (owner, group) = (Some(Uid::from_raw(ID)), Some(Gid::from_raw(ID)));
    rustix::fs::chown(dir, owner, group)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500))?;
    for (file, pem) in [
        ("client-ca.pem", api.tls.client_ca.pem()),
        ("cert.pem", api.tls.certificate.pem()),
        ("key.pem", api.tls.private_key.expose_pem()),
    ] {
        let path = dir.join(file);
        std::fs::write(&path, pem)?;
        rustix::fs::chown(&path, owner, group)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400))?;
    }
    Ok(())
}

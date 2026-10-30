//! The APIs machine-controller calls, each on its unix socket, connected on first use.

use std::path::Path;
use std::path::PathBuf;

use tonic::transport::Channel;

/// The controllers' APIs, machine-apiproxy's and serviced's, and where serviced's layers are.
#[derive(Debug)]
pub struct Controllers {
    pub network: Upstream,
    pub storage: Upstream,
    pub time: Upstream,
    /// workload-controller, which also serves `hardened.workloads.v1.Workloads`.
    pub workload: Upstream,
    /// kubelet-controller, on Kubernetes targets only.
    pub kubelet: Upstream,
    /// machine-apiproxy, whose socket exists once it is enabled.
    pub apiproxy: Upstream,
    /// trust-controller, which serves `hardened.attestation.v1.Attestation`; without a TPM, its
    /// socket does not exist.
    pub trust: Upstream,
    pub serviced: Upstream,
    /// Below which the layers' directories are: `/` but for fakes.
    pub root: PathBuf,
}

impl Controllers {
    /// The machine's.
    #[must_use]
    pub fn system() -> Self {
        Self {
            network: Upstream::new(network_controller::SOCKET),
            storage: Upstream::new(storage_controller::SOCKET),
            time: Upstream::new(time_controller::SOCKET),
            workload: Upstream::new(workload_controller::SOCKET),
            kubelet: Upstream::new(kubelet_controller::SOCKET),
            apiproxy: Upstream::new(machine_apiproxy::SOCKET),
            trust: Upstream::new(trust_controller::SOCKET),
            serviced: Upstream::new(libserviced::SOCKET),
            root: PathBuf::from("/"),
        }
    }

    /// Sockets named after their service in `dir`, and the layers below it, for fakes.
    #[cfg(test)]
    #[must_use]
    pub fn in_dir(dir: &Path) -> Self {
        let upstream = |name: &str| Upstream::new(dir.join(format!("{name}.sock")));
        Self {
            network: upstream("network-controller"),
            storage: upstream("storage-controller"),
            time: upstream("time-controller"),
            workload: upstream("workload-controller"),
            kubelet: upstream("kubelet-controller"),
            apiproxy: upstream("machine-apiproxy"),
            trust: upstream("trust-controller"),
            serviced: upstream("serviced"),
            root: dir.to_owned(),
        }
    }
}

/// A service's API, connected on the first call: a socket-activated service starts then, not
/// when machine-controller does.
#[derive(Debug)]
pub struct Upstream {
    socket: PathBuf,
    channel: Channel,
}

impl Upstream {
    /// The API on `socket`. Created within a tokio runtime.
    #[must_use]
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        let socket = socket.into();
        Self {
            channel: controllers_helpers::lazy_channel(&socket),
            socket,
        }
    }

    /// Whether its socket exists: serviced creates none for a service that does not exist or
    /// whose condition is false.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.socket.exists()
    }

    /// Its socket.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// The channel; its calls fail with `unavailable` while the socket cannot be connected to.
    #[must_use]
    pub fn channel(&self) -> Channel {
        self.channel.clone()
    }
}

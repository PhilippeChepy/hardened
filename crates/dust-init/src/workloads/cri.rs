//! A thin, typed client for the CRI services (`runtime.v1`) of containerd's CRI plugin.

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use cri_api::v1::{
    ContainerConfig, ContainerEventResponse, ContainerState, ContainerStatusRequest, CreateContainerRequest,
    GetEventsRequest, ImageSpec, ImageStatusRequest, ListPodSandboxRequest, PodSandboxConfig, PodSandboxFilter,
    PullImageRequest, RemoveContainerRequest, RemovePodSandboxRequest, RunPodSandboxRequest, StartContainerRequest,
    StatusRequest, StopContainerRequest, StopPodSandboxRequest, VersionRequest, VersionResponse,
    image_service_client::ImageServiceClient, runtime_service_client::RuntimeServiceClient,
};
use hyper_util::rt::TokioIo;
use tokio::net::UnixStream;
use tonic::codec::Streaming;
use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status};

use crate::types::ImageRef;

/// The CRI API version dust-init speaks.
const API_VERSION: &str = "v1";
/// The runtime condition containerd reports once it can run containers.
const RUNTIME_READY: &str = "RuntimeReady";
const RETRY_INTERVAL: Duration = Duration::from_millis(250);

/// Defines an opaque ID newtype, so sandbox and container IDs cannot be mixed up.
macro_rules! id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl From<String> for $name {
            fn from(id: String) -> Self {
                Self(id)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

id!(
    /// A pod sandbox, as named by the runtime.
    SandboxId
);
id!(
    /// A container, as named by the runtime.
    ContainerId
);
id!(
    /// An image of the runtime's store: the digest of its configuration.
    ImageId
);

impl ImageId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The state of a container as the runtime reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Observed {
    Created,
    Running,
    Exited { code: i32 },
    Unknown,
}

/// Opens a channel to containerd's socket (CRI and native services share it).
pub async fn dial(socket: &Path) -> anyhow::Result<Channel> {
    let socket = PathBuf::from(socket);
    // The URI is required by the HTTP/2 layer but unused: the connector dials the socket.
    let channel = Endpoint::from_static("http://containerd")
        .connect_with_connector(tower::service_fn(move |_| {
            let socket = socket.clone();
            async move { UnixStream::connect(socket).await.map(TokioIo::new) }
        }))
        .await?;
    Ok(channel)
}

#[derive(Clone)]
pub struct Cri {
    runtime: RuntimeServiceClient<Channel>,
    images: ImageServiceClient<Channel>,
}

impl Cri {
    /// Connects to containerd, retrying until `timeout` while it starts, and until its CRI
    /// runtime is ready. Returns the client, the channel (for the native services) and the
    /// runtime's version.
    pub async fn connect(socket: &Path, timeout: Duration) -> anyhow::Result<(Self, Channel, VersionResponse)> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match Self::try_connect(socket).await {
                Ok(connected) => return Ok(connected),
                Err(e) if tokio::time::Instant::now() < deadline => {
                    tracing::debug!("containerd is not ready yet: {e:#}");
                    tokio::time::sleep(RETRY_INTERVAL).await;
                }
                Err(e) => {
                    return Err(e.context(format!(
                        "containerd's CRI runtime was not ready on {} within {timeout:?}",
                        socket.display()
                    )));
                }
            }
        }
    }

    async fn try_connect(socket: &Path) -> anyhow::Result<(Self, Channel, VersionResponse)> {
        let channel = dial(socket).await?;
        let mut cri = Self {
            runtime: RuntimeServiceClient::new(channel.clone()),
            images: ImageServiceClient::new(channel.clone()),
        };
        let version = cri
            .runtime
            .version(VersionRequest {
                version: API_VERSION.into(),
            })
            .await?
            .into_inner();
        cri.ensure_ready().await?;
        Ok((cri, channel, version))
    }

    /// Fails unless the runtime reports `RuntimeReady`. Networking is not required: pods use the
    /// host network, so `NetworkReady` stays false without CNI.
    async fn ensure_ready(&mut self) -> anyhow::Result<()> {
        let status = self
            .runtime
            .status(StatusRequest { verbose: false })
            .await?
            .into_inner();
        let conditions = status.status.map(|s| s.conditions).unwrap_or_default();
        match conditions.iter().find(|c| c.r#type == RUNTIME_READY) {
            Some(condition) if condition.status => Ok(()),
            Some(condition) => anyhow::bail!("the runtime is not ready: {} {}", condition.reason, condition.message),
            None => anyhow::bail!("the runtime reports no {RUNTIME_READY} condition"),
        }
    }

    /// The image `reference` resolves to in the runtime's store, if present.
    pub async fn image_id(&self, reference: &ImageRef) -> Result<Option<ImageId>, Status> {
        let response = self
            .images
            .clone()
            .image_status(ImageStatusRequest {
                image: Some(image_spec(reference.as_str())),
                verbose: false,
            })
            .await?
            .into_inner();
        Ok(response
            .image
            .map(|image| ImageId(image.id))
            .filter(|id| !id.0.is_empty()))
    }

    /// Pulls `reference` with the runtime's registry configuration.
    pub async fn pull(&self, reference: &ImageRef) -> Result<ImageId, Status> {
        let response = self
            .images
            .clone()
            .pull_image(PullImageRequest {
                image: Some(image_spec(reference.as_str())),
                auth: None,
                sandbox_config: None,
            })
            .await?
            .into_inner();
        Ok(ImageId(response.image_ref))
    }

    pub async fn run_sandbox(&self, config: PodSandboxConfig) -> Result<SandboxId, Status> {
        let response = self
            .runtime
            .clone()
            .run_pod_sandbox(RunPodSandboxRequest {
                config: Some(config),
                runtime_handler: String::new(),
            })
            .await?
            .into_inner();
        Ok(SandboxId(response.pod_sandbox_id))
    }

    /// Stops a sandbox and every container in it.
    pub async fn stop_sandbox(&self, id: &SandboxId) -> Result<(), Status> {
        let request = StopPodSandboxRequest {
            pod_sandbox_id: id.0.clone(),
        };
        ignore_not_found(self.runtime.clone().stop_pod_sandbox(request).await)
    }

    /// Removes a sandbox and every container in it, stopping them first if needed.
    pub async fn remove_sandbox(&self, id: &SandboxId) -> Result<(), Status> {
        let request = RemovePodSandboxRequest {
            pod_sandbox_id: id.0.clone(),
        };
        ignore_not_found(self.runtime.clone().remove_pod_sandbox(request).await)
    }

    /// The sandboxes whose labels include all of `labels`, with their labels.
    pub async fn sandboxes(
        &self,
        labels: HashMap<String, String>,
    ) -> Result<Vec<(SandboxId, HashMap<String, String>)>, Status> {
        let response = self
            .runtime
            .clone()
            .list_pod_sandbox(ListPodSandboxRequest {
                filter: Some(PodSandboxFilter {
                    label_selector: labels,
                    ..Default::default()
                }),
            })
            .await?
            .into_inner();
        Ok(response
            .items
            .into_iter()
            .map(|sandbox| (SandboxId(sandbox.id), sandbox.labels))
            .collect())
    }

    pub async fn create_container(
        &self,
        sandbox: &SandboxId,
        config: ContainerConfig,
        sandbox_config: PodSandboxConfig,
    ) -> Result<ContainerId, Status> {
        let response = self
            .runtime
            .clone()
            .create_container(CreateContainerRequest {
                pod_sandbox_id: sandbox.0.clone(),
                config: Some(config),
                sandbox_config: Some(sandbox_config),
            })
            .await?
            .into_inner();
        Ok(ContainerId(response.container_id))
    }

    pub async fn start_container(&self, id: &ContainerId) -> Result<(), Status> {
        self.runtime
            .clone()
            .start_container(StartContainerRequest {
                container_id: id.0.clone(),
            })
            .await?;
        Ok(())
    }

    /// Sends the stop signal, then SIGKILL after `grace`; returns once the container stopped.
    pub async fn stop_container(&self, id: &ContainerId, grace: Duration) -> Result<(), Status> {
        let request = StopContainerRequest {
            container_id: id.0.clone(),
            timeout: timeout_secs(grace),
        };
        ignore_not_found(self.runtime.clone().stop_container(request).await)
    }

    /// Removes a container, killing it first if needed.
    pub async fn remove_container(&self, id: &ContainerId) -> Result<(), Status> {
        let request = RemoveContainerRequest {
            container_id: id.0.clone(),
        };
        ignore_not_found(self.runtime.clone().remove_container(request).await)
    }

    pub async fn container_state(&self, id: &ContainerId) -> Result<Observed, Status> {
        let response = self
            .runtime
            .clone()
            .container_status(ContainerStatusRequest {
                container_id: id.0.clone(),
                verbose: false,
            })
            .await?
            .into_inner();
        let status = response
            .status
            .ok_or_else(|| Status::internal(format!("no status for container {id}")))?;
        Ok(match ContainerState::try_from(status.state) {
            Ok(ContainerState::ContainerCreated) => Observed::Created,
            Ok(ContainerState::ContainerRunning) => Observed::Running,
            Ok(ContainerState::ContainerExited) => Observed::Exited { code: status.exit_code },
            Ok(ContainerState::ContainerUnknown) | Err(_) => Observed::Unknown,
        })
    }

    /// The host pid of the container's process. CRI only exposes it in the verbose `info` of
    /// containerd's ContainerStatus, so `None` when the runtime does not provide it.
    pub async fn container_pid(&self, id: &ContainerId) -> Option<u32> {
        let response = self
            .runtime
            .clone()
            .container_status(ContainerStatusRequest {
                container_id: id.0.clone(),
                verbose: true,
            })
            .await;
        match response {
            Ok(response) => pid_from_info(&response.into_inner().info),
            Err(status) => {
                tracing::debug!("container {id}: reading its verbose status: {status}");
                None
            }
        }
    }

    /// The runtime's stream of container lifecycle events.
    pub async fn container_events(&self) -> Result<Streaming<ContainerEventResponse>, Status> {
        Ok(self
            .runtime
            .clone()
            .get_container_events(GetEventsRequest {})
            .await?
            .into_inner())
    }
}

fn image_spec(image: &str) -> ImageSpec {
    ImageSpec {
        image: image.into(),
        ..Default::default()
    }
}

/// CRI timeouts are whole seconds: round up, so a grace period is never shortened.
fn timeout_secs(grace: Duration) -> i64 {
    let secs = grace.as_secs() + u64::from(grace.subsec_nanos() > 0);
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// containerd's verbose container info: `{"info": "{\"pid\": 42, …}"}`.
fn pid_from_info(info: &HashMap<String, String>) -> Option<u32> {
    #[derive(serde::Deserialize)]
    struct Info {
        pid: u32,
    }
    let info: Info = serde_json::from_str(info.get("info")?).ok()?;
    // A pid of 0 means the container has no running process.
    Some(info.pid).filter(|&pid| pid != 0)
}

fn ignore_not_found<T>(response: Result<T, Status>) -> Result<(), Status> {
    match response {
        Err(status) if status.code() != Code::NotFound => Err(status),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_round_up_to_seconds() {
        assert_eq!(timeout_secs(Duration::ZERO), 0);
        assert_eq!(timeout_secs(Duration::from_secs(10)), 10);
        assert_eq!(timeout_secs(Duration::from_millis(10_001)), 11);
    }

    #[test]
    fn reads_the_pid_from_verbose_info() {
        let info = |json: &str| HashMap::from([("info".to_owned(), json.to_owned())]);
        assert_eq!(
            pid_from_info(&info(r#"{"sandboxID":"abc","pid":4242,"removing":false}"#)),
            Some(4242)
        );
        assert_eq!(pid_from_info(&info(r#"{"pid":0}"#)), None);
        assert_eq!(pid_from_info(&info("not json")), None);
        assert_eq!(pid_from_info(&HashMap::new()), None);
    }
}

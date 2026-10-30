//! The machine's API, which machine-apiproxy serves over mutual TLS: `Machine` answered here,
//! from what machine-controller knows, the controllers' APIs and serviced's; `Workloads` and
//! `Attestation` forwarded. Its socket allows machine-apiproxy only, which checks its clients'
//! roles.

use std::pin::Pin;
use std::sync::Arc;

use controllers_helpers::Forwarder;
use libserviced::api;
use libserviced::api::serviced_client::ServicedClient;
use machine_controller::machine;
use machine_controller::machine::machine_server::Machine;
use machine_controller::machine::machine_server::MachineServer;
use storage_controller::storage;
use storage_controller::storage::storage_controller_client::StorageControllerClient;
use time_controller::time;
use time_controller::time::time_controller_client::TimeControllerClient;
use tokio_stream::Stream;
use tokio_stream::StreamExt;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Channel;
use tonic::transport::Server;
use tonic::transport::server::Router;
use trust_controller::attestation::attestation_server::AttestationServer;
use workload_controller::workloads::workloads_server::WorkloadsServer;

use crate::controllers::Controllers;
use crate::machine_identity::MachineIdentity;

/// The API's services, for the machine of `identity` configured with `settings` (without
/// secrets).
#[must_use]
pub fn router(
    controllers: Arc<Controllers>,
    identity: MachineIdentity,
    settings: machine::Settings,
) -> Router {
    Server::builder()
        .add_service(MachineServer::new(MachineService {
            controllers: controllers.clone(),
            identity,
            settings,
        }))
        .add_service(Forwarder::<WorkloadsServer<()>>::new(
            controllers.workload.socket(),
            "workload-controller does not run",
        ))
        // trust-controller's socket exists only on a machine with a TPM.
        .add_service(Forwarder::<AttestationServer<()>>::new(
            controllers.trust.socket(),
            "no TPM",
        ))
}

/// Serves `Machine`.
struct MachineService {
    controllers: Arc<Controllers>,
    identity: MachineIdentity,
    /// Without secrets.
    settings: machine::Settings,
}

impl MachineService {
    fn serviced(&self) -> ServicedClient<Channel> {
        ServicedClient::new(self.controllers.serviced.channel())
    }
}

#[tonic::async_trait]
impl Machine for MachineService {
    async fn version(&self, _: Request<()>) -> Result<Response<machine::VersionResponse>, Status> {
        Ok(Response::new(self.identity.to_version()))
    }

    type LogsStream = Pin<Box<dyn Stream<Item = Result<machine::LogEntry, Status>> + Send>>;

    async fn logs(
        &self,
        request: Request<machine::LogsRequest>,
    ) -> Result<Response<Self::LogsStream>, Status> {
        let machine::LogsRequest { follow, tail } = request.into_inner();
        let request = api::LogsRequest {
            // serviced's own log.
            service: String::new(),
            tail,
            follow,
        };
        let lines = self.serviced().logs(request).await?.into_inner();
        let entries = lines.map(|line| {
            line.map(|line| machine::LogEntry {
                time: line.time,
                level: line.level,
                target: line.target,
                message: line.text,
            })
        });
        Ok(Response::new(Box::pin(entries)))
    }

    async fn get_settings(&self, _: Request<()>) -> Result<Response<machine::Settings>, Status> {
        Ok(Response::new(self.settings.clone()))
    }

    async fn storage(&self, _: Request<()>) -> Result<Response<storage::State>, Status> {
        let channel = self.controllers.storage.channel();
        StorageControllerClient::new(channel).get_state(()).await
    }

    async fn time(&self, _: Request<()>) -> Result<Response<time::Status>, Status> {
        let channel = self.controllers.time.channel();
        TimeControllerClient::new(channel).get_status(()).await
    }

    async fn reboot(&self, _: Request<()>) -> Result<Response<()>, Status> {
        tracing::info!("reboot requested");
        self.serviced().reboot(()).await
    }

    async fn shutdown(&self, _: Request<()>) -> Result<Response<()>, Status> {
        tracing::info!("shutdown requested");
        self.serviced().power_off(()).await
    }
}

#[cfg(test)]
mod tests {
    use machine_controller::UserData;
    use machine_controller::machine::machine_client::MachineClient;
    use tokio::net::UnixListener;
    use tokio_stream::wrappers::UnixListenerStream;
    use tonic::Code;
    use trust_controller::attestation;
    use trust_controller::attestation::attestation_client::AttestationClient;
    use workload_controller::workloads;
    use workload_controller::workloads::workloads_client::WorkloadsClient;

    use super::*;
    use crate::fake_controllers::FakeControllers;
    use crate::metadata::Platform;

    struct Harness {
        fakes: FakeControllers,
        channel: Channel,
        _dir: tempfile::TempDir,
    }

    /// Serves the API, from fake controllers, on a socket of its own.
    async fn start() -> Harness {
        let fakes = FakeControllers::start().await;
        let settings = UserData::parse(crate::fake_controllers::api_user_data().as_bytes())
            .unwrap()
            .settings;
        let identity = MachineIdentity {
            os_version: "1.0".to_owned(),
            kernel: "6.18.0".to_owned(),
            platform: Some(Platform::Qemu),
            instance_id: Some("i-1".to_owned()),
            hostname: "node-1".parse().unwrap(),
            boot_id: None,
            booted_at_unix_ms: 1_700_000_000_000,
        };
        let router = router(
            fakes.controllers.clone(),
            identity,
            settings.to_proto_without_secrets(),
        );
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        tokio::spawn(router.serve_with_incoming(UnixListenerStream::new(listener)));
        let channel = controllers_helpers::channel(&socket).await.unwrap();
        Harness {
            fakes,
            channel,
            _dir: dir,
        }
    }

    #[tokio::test]
    async fn machine_answers_from_its_state_and_the_controllers() {
        let harness = start().await;
        let mut machine = MachineClient::new(harness.channel.clone());

        let version = machine.version(()).await.unwrap().into_inner();
        assert_eq!(version.hostname, "node-1");
        assert_eq!(version.instance_id, "i-1");
        assert_eq!(version.booted_at.unwrap().seconds, 1_700_000_000);

        let settings = machine.get_settings(()).await.unwrap().into_inner();
        let tls = settings.api.unwrap().tls.unwrap();
        assert!(!tls.certificate.is_empty());
        assert!(tls.private_key.is_empty(), "secrets are left out");

        let storage = machine.storage(()).await.unwrap().into_inner();
        assert_eq!(storage.size_bytes, 1 << 30);
        let time = machine.time(()).await.unwrap().into_inner();
        assert!(time.clock.unwrap().synchronized);

        let request = machine::LogsRequest {
            follow: true,
            tail: 10,
        };
        let entries: Vec<machine::LogEntry> = machine
            .logs(request)
            .await
            .unwrap()
            .into_inner()
            .map(Result::unwrap)
            .collect()
            .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].message, "boot complete");
        assert_eq!(entries[0].target, "serviced");

        machine.reboot(()).await.unwrap();
        machine.shutdown(()).await.unwrap();
        assert_eq!(
            harness.fakes.calls(),
            [
                "serviced Logs service=\"\" tail=10 follow=true",
                "serviced Reboot",
                "serviced PowerOff",
            ]
        );
    }

    #[tokio::test]
    async fn workloads_are_forwarded_to_workload_controller() {
        let harness = start().await;
        let mut workloads = WorkloadsClient::new(harness.channel.clone());

        let list = workloads.list(()).await.unwrap().into_inner();
        assert_eq!(list.workloads[0].name, "web");
        let applied = workloads
            .apply(workloads::ApplyWorkloadRequest {
                name: "db".to_owned(),
                spec: None,
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(applied.name, "db");
        let error = workloads
            .remove(workloads::WorkloadRef {
                name: "nope".to_owned(),
            })
            .await
            .unwrap_err();
        assert_eq!(error.code(), Code::NotFound, "statuses pass through");
        assert_eq!(error.message(), "no workload nope");

        let request = workloads::WorkloadLogsRequest {
            name: "web".to_owned(),
            ..workloads::WorkloadLogsRequest::default()
        };
        let chunks: Vec<Vec<u8>> = workloads
            .logs(request)
            .await
            .unwrap()
            .into_inner()
            .map(|chunk| chunk.unwrap().data)
            .collect()
            .await;
        assert_eq!(chunks, [b"first\n".to_vec(), b"second\n".to_vec()]);
        assert_eq!(harness.fakes.calls(), ["workload-controller Apply db"]);
    }

    #[tokio::test]
    async fn attestation_needs_a_tpm() {
        let harness = start().await;
        let mut attestation = AttestationClient::new(harness.channel.clone());
        let request = attestation::PcrsRequest::default();
        let error = attestation.pcrs(request.clone()).await.unwrap_err();
        assert_eq!(error.code(), Code::Unavailable);
        assert_eq!(error.message(), "no TPM");

        harness.fakes.start_trust();
        let pcrs = attestation.pcrs(request).await.unwrap().into_inner();
        assert_eq!(pcrs.values[0].index, 7);
        let error = attestation.event_log(()).await.unwrap_err();
        assert_eq!(error.code(), Code::FailedPrecondition);
    }
}

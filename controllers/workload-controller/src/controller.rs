//! `WorkloadController`: user-data's workloads, as services of serviced's runtime layer.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;

use libserviced::api::serviced_client::ServicedClient;
use libserviced::client;
use libserviced::definition;
use libserviced::definition::Layer;
use tokio::sync::Mutex;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Channel;
use workload_controller::workload;
use workload_controller::workload::workload_controller_server::WorkloadController;

use crate::configuration::Configuration;
use crate::defined_workload;
use crate::service_file;

/// The configuration, shared with the `Workloads` service; `None` until the first one. Held
/// while services are written, so a workload is not applied through the API while user-data
/// claims its name, and one file is written at a time.
pub type SharedConfiguration = Arc<Mutex<Option<Configuration>>>;

/// Serves `WorkloadController`.
pub struct Controller {
    serviced: ServicedClient<Channel>,
    /// Below which serviced's layers are: `/` but in tests.
    root: PathBuf,
    configuration: SharedConfiguration,
    state: PathBuf,
}

impl Controller {
    /// A controller writing services in serviced's layers below `root`, then reloading
    /// `serviced`, and keeping its configuration in `state`.
    #[must_use]
    pub fn new(
        serviced: ServicedClient<Channel>,
        root: PathBuf,
        configuration: SharedConfiguration,
        state: PathBuf,
    ) -> Self {
        Self {
            serviced,
            root,
            configuration,
            state,
        }
    }

    /// Applies the configuration kept from an earlier run, if any. A failure is logged: the
    /// next `Configure` applies it again.
    pub async fn restore(&self) {
        let configuration = match Configuration::load(&self.state) {
            Ok(Some(configuration)) => configuration,
            Ok(None) => return,
            Err(error) => {
                let state = self.state.display();
                tracing::error!(%state, %error, "cannot read the kept configuration");
                return;
            }
        };
        let mut current = self.configuration.lock().await;
        if let Err(status) = self.apply(&configuration).await {
            tracing::error!(error = %status.message(), "cannot apply the kept configuration");
        }
        *current = Some(configuration);
    }

    /// Writes the services of the enabled workloads in the runtime layer, removes those of
    /// workloads no longer declared, then reloads serviced. An unchanged file changes nothing.
    /// User-data wins over the API: an API workload of a name user-data declares is removed
    /// (Apply refuses those names, but user-data can change across boots).
    async fn apply(&self, configuration: &Configuration) -> Result<(), Status> {
        let mut serviced = self.serviced.clone();
        let mut declared = BTreeSet::new();
        let mut enabled = BTreeSet::new();
        for (name, container) in configuration.workloads() {
            let service = service_file::service_name(name);
            declared.insert(service.to_string());
            if !container.enabled {
                continue;
            }
            let contents = service_file::to_toml(name, &container.workload);
            definition::write_service_file(&self.root, Layer::Runtime, &service, &contents)
                .map_err(service_file_error)?;
            tracing::info!(
                workload = %name,
                image = %container.workload.image,
                "workload service written"
            );
            enabled.insert(service.to_string());
        }

        let services = serviced
            .list_services(())
            .await
            .map_err(|status| client::call_error("ListServices", status))?
            .into_inner()
            .services;
        for service in services {
            let Some(workload) = service_file::workload_name(&service.name) else {
                continue;
            };
            let name = service_file::service_name(&workload);
            if defined_workload::has_layer(&service, Layer::Runtime)
                && !enabled.contains(&service.name)
            {
                definition::remove_service_file(&self.root, Layer::Runtime, &name)
                    .map_err(service_file_error)?;
                tracing::info!(service = %service.name, "stale workload service removed");
            }
            if defined_workload::has_layer(&service, Layer::Persistent)
                && declared.contains(&service.name)
            {
                definition::remove_service_file(&self.root, Layer::Persistent, &name)
                    .map_err(service_file_error)?;
                tracing::warn!(
                    service = %service.name,
                    "the API's workload of a name user-data declares removed"
                );
            }
        }
        client::reload(&mut serviced).await
    }
}

/// A service file workload-controller cannot write or remove: its own failure.
#[must_use]
pub fn service_file_error(error: definition::Error) -> Status {
    Status::internal(format!("writing serviced's service files: {error}"))
}

#[tonic::async_trait]
impl WorkloadController for Controller {
    async fn configure(
        &self,
        request: Request<workload::Configuration>,
    ) -> Result<Response<()>, Status> {
        let configuration = Configuration::try_from(request.into_inner())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let mut current = self.configuration.lock().await;
        configuration.save(&self.state).map_err(|error| {
            Status::internal(format!("keeping {}: {error}", self.state.display()))
        })?;
        let applied = self.apply(&configuration).await;
        tracing::info!(workloads = configuration.workloads().count(), "configured");
        *current = Some(configuration);
        applied.map(Response::new)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use libserviced::definition::Service;
    use libserviced::testing::Call;
    use libserviced::testing::FakeServiced;
    use tonic::Code;
    use workload_controller::workloads;

    use super::*;
    use crate::service_file::tests::declared;
    use crate::service_file::tests::workload;

    fn configuration(
        workloads: Vec<workloads::DeclaredWorkload>,
    ) -> Request<workload::Configuration> {
        Request::new(workload::Configuration { workloads })
    }

    struct Test {
        dir: tempfile::TempDir,
        fake: FakeServiced,
        controller: Controller,
    }

    impl Test {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (fake, client) = FakeServiced::start(dir.path(), dir.path()).await;
            let controller = Controller::new(
                client,
                dir.path().to_owned(),
                SharedConfiguration::default(),
                dir.path().join("state.json"),
            );
            Self {
                dir,
                fake,
                controller,
            }
        }
    }

    #[tokio::test]
    async fn user_data_wins_over_the_apis_workload_of_the_same_name() {
        let test = Test::new().await;
        let fake = &test.fake;
        fake.put(
            Layer::Persistent,
            "workload-web",
            "exec = [\"/bin/true\"]\n",
        );
        fake.put(
            Layer::Persistent,
            "workload-off",
            "exec = [\"/bin/true\"]\n",
        );
        fake.put(Layer::Persistent, "workload-db", "exec = [\"/bin/true\"]\n");

        let request = configuration(vec![declared("web", true), declared("off", false)]);
        test.controller.configure(request).await.unwrap();
        assert_eq!(fake.take_calls(), [Call::Reload]);
        assert_eq!(
            fake.names(),
            [
                (Layer::Runtime, "workload-web".into()),
                (Layer::Persistent, "workload-db".into()),
            ]
        );
    }

    #[tokio::test]
    async fn writes_the_enabled_workloads_and_deletes_the_stale_ones() {
        let test = Test::new().await;
        let fake = &test.fake;
        fake.put(
            Layer::Image,
            "containerd",
            "exec = [\"/usr/bin/containerd\"]\n",
        );
        fake.put(Layer::Runtime, "kubelet", "enabled = true\n");
        fake.put(Layer::Runtime, "workload-old", "exec = [\"/bin/true\"]\n");
        fake.put(
            Layer::Persistent,
            "workload-api",
            "exec = [\"/bin/true\"]\n",
        );

        let request = configuration(vec![declared("web", true), declared("off", false)]);
        test.controller.configure(request).await.unwrap();
        assert_eq!(fake.take_calls(), [Call::Reload]);
        let web: Service =
            toml::from_str(&fake.file(Layer::Runtime, "workload-web").unwrap()).unwrap();
        assert_eq!(service_file::to_workload(&web), Some(workload()));
        assert_eq!(
            fake.names(),
            [
                (Layer::Image, "containerd".into()),
                (Layer::Runtime, "kubelet".into()),
                (Layer::Runtime, "workload-web".into()),
                (Layer::Persistent, "workload-api".into()),
            ]
        );

        // Again, without web: idempotent, then removed.
        let request = configuration(vec![declared("web", true)]);
        test.controller.configure(request).await.unwrap();
        assert_eq!(fake.take_calls(), [Call::Reload]);
        test.controller
            .configure(configuration(Vec::new()))
            .await
            .unwrap();
        assert_eq!(fake.take_calls(), [Call::Reload]);
        assert_eq!(fake.file(Layer::Runtime, "workload-web"), None);
    }

    #[tokio::test]
    async fn refuses_invalid_configurations() {
        let test = Test::new().await;
        let mut bad = declared("web", true);
        bad.spec.as_mut().unwrap().image = String::new();
        let status = test
            .controller
            .configure(configuration(vec![bad]))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().starts_with("workloads[0].spec.image"));
        assert_eq!(test.fake.take_calls(), []);
        assert!(test.controller.configuration.lock().await.is_none());
        assert!(!test.dir.path().join("state.json").exists());
    }

    #[tokio::test]
    async fn a_restarted_controller_restores_its_configuration() {
        let test = Test::new().await;
        let request = configuration(vec![declared("web", true), declared("off", false)]);
        test.controller.configure(request).await.unwrap();
        let configured = test.controller.configuration.lock().await.clone();
        test.fake.take_calls();

        let other = test.dir.path().join("restarted");
        std::fs::create_dir(&other).unwrap();
        fs::remove_file(
            test.dir
                .path()
                .join("run/serviced/services/workload-web.toml"),
        )
        .unwrap();
        let (fake, client) = FakeServiced::start(&other, test.dir.path()).await;
        let restarted = Controller::new(
            client,
            test.dir.path().to_owned(),
            SharedConfiguration::default(),
            test.dir.path().join("state.json"),
        );
        restarted.restore().await;
        assert!(configured.is_some());
        assert_eq!(*restarted.configuration.lock().await, configured);
        assert_eq!(fake.take_calls(), [Call::Reload]);
        assert!(fake.file(Layer::Runtime, "workload-web").is_some());
    }
}

//! `KubeletController`: kubelet's files, and its service enabled with a drop-in in serviced's
//! runtime layer, merged over the image's disabled `kubelet` service.

use std::path::PathBuf;

use controllers_helpers::Hostname;
use controllers_helpers::InvalidMessage;
use controllers_helpers::invalid_message::FieldResult;
use controllers_helpers::invalid_message::WithinResult;
use kubelet_controller::KubeletConfig;
use kubelet_controller::kubelet;
use kubelet_controller::kubelet::kubelet_controller_server::KubeletController;
use libserviced::api::ServiceRef;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::client;
use libserviced::definition;
use libserviced::definition::Layer;
use libserviced::definition::ServiceName;
use libserviced::notify;
use tokio::sync::Mutex;
use tonic::Code;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Channel;

use crate::rendered;
use crate::rendered::Rendered;
use crate::state::State;

const KUBELET: &str = "kubelet";
const KUBELET_SERVICE: ServiceName = ServiceName::from_static(KUBELET);

/// Serves `KubeletController`.
pub struct Controller {
    serviced: ServicedClient<Channel>,
    /// What kubelet runs with since the last configuration; `None` when it does not run.
    current: Mutex<Option<Rendered>>,
    /// Where kubelet's files and its drop-in in serviced's runtime layer are written: `/` but in
    /// tests.
    root: PathBuf,
    state: PathBuf,
}

impl Controller {
    /// A controller writing kubelet's files and its drop-in below `root`, then reloading
    /// `serviced`, and keeping its state in `state`.
    #[must_use]
    pub fn new(serviced: ServicedClient<Channel>, root: PathBuf, state: PathBuf) -> Self {
        Self {
            serviced,
            current: Mutex::new(None),
            root,
            state,
        }
    }

    /// Applies the state kept from an earlier run, if any, and then is ready. A failure is
    /// logged: the next `Configure` applies it again.
    pub async fn restore(&self) {
        let state = match State::load(&self.state) {
            Ok(Some(state)) => state,
            Ok(None) => return,
            Err(error) => {
                let state = self.state.display();
                tracing::error!(%state, %error, "cannot read the kept state");
                return;
            }
        };
        let mut current = self.current.lock().await;
        match self.apply(None, &state).await {
            Ok(()) => ready(),
            Err(status) => {
                tracing::error!(error = %status.message(), "cannot apply the kept state");
            }
        }
        *current = state.kubelet;
    }

    /// Writes kubelet's files and enables it, or disables it. kubelet is restarted when what it
    /// runs with changed since `previous`, so that it reads its files again.
    async fn apply(&self, previous: Option<&Rendered>, state: &State) -> Result<(), Status> {
        let mut serviced = self.serviced.clone();
        let service = || ServiceRef {
            name: KUBELET.to_owned(),
        };
        let name = KUBELET_SERVICE;
        let Some(kubelet) = &state.kubelet else {
            definition::remove_service_file(&self.root, Layer::Runtime, &name)
                .map_err(|error| Status::internal(format!("disabling kubelet: {error}")))?;
            client::reload(&mut serviced).await?;
            return match serviced.stop(service()).await {
                Ok(_) => {
                    tracing::info!("kubelet disabled");
                    Ok(())
                }
                Err(status) if status.code() == Code::NotFound => Ok(()),
                Err(status) => Err(client::call_error("Stop", status)),
            };
        };

        kubelet
            .write(&self.root)
            .map_err(|error| Status::internal(format!("writing kubelet's files: {error}")))?;
        definition::write_service_file(&self.root, Layer::Runtime, &name, &drop_in(kubelet))
            .map_err(|error| Status::internal(format!("enabling kubelet: {error}")))?;
        client::reload(&mut serviced).await?;
        let changed = previous.is_some_and(|previous| previous != kubelet);
        if changed {
            serviced
                .restart(service())
                .await
                .map_err(|status| client::call_error("Restart", status))?;
            tracing::info!("kubelet restarted with its new configuration");
        } else {
            serviced
                .start(service())
                .await
                .map_err(|status| client::call_error("Start", status))?;
            tracing::info!("kubelet enabled");
        }
        Ok(())
    }
}

#[tonic::async_trait]
impl KubeletController for Controller {
    async fn configure(
        &self,
        request: Request<kubelet::Configuration>,
    ) -> Result<Response<()>, Status> {
        let state = to_state(request.into_inner())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        let mut current = self.current.lock().await;
        state.save(&self.state).map_err(|error| {
            Status::internal(format!("keeping {}: {error}", self.state.display()))
        })?;
        let applied = self.apply(current.as_ref(), &state).await;
        *current = state.kubelet;
        applied?;
        ready();
        Ok(Response::new(()))
    }
}

/// What a configuration makes kubelet run with.
fn to_state(message: kubelet::Configuration) -> Result<State, InvalidMessage> {
    let Some(kubelet) = message.kubelet else {
        return Ok(State { kubelet: None });
    };
    let config = KubeletConfig::try_from(kubelet).within("kubelet")?;
    let node_name = Hostname::try_from(message.node_name).field("node_name")?;
    Ok(State {
        kubelet: Some(rendered::render(&config, &node_name)),
    })
}

/// The drop-in enabling kubelet with its arguments, merged over the image's service.
#[must_use]
fn drop_in(kubelet: &Rendered) -> String {
    let mut exec = vec![rendered::PROGRAM.to_owned()];
    exec.extend_from_slice(kubelet.args());
    let mut service = toml::Table::new();
    service.insert("enabled".into(), true.into());
    service.insert("exec".into(), exec.into());
    service.to_string()
}

/// Tells serviced kubelet-controller is ready: it applied a configuration. Again on later ones,
/// which serviced ignores.
fn ready() {
    if let Err(error) = notify::ready() {
        tracing::warn!(%error, "cannot notify serviced");
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::sync::LazyLock;

    use libserviced::definition;
    use libserviced::testing::Call;
    use libserviced::testing::FakeServiced;

    use super::*;
    use crate::rendered::tests::config;
    use crate::rendered::tests::static_pods;

    /// The image's kubelet service.
    const IMAGE_KUBELET: &str = include_str!(
        "../../../specs/targets/kubernetes-1-37/components/kubelet/services/kubelet.toml"
    );

    struct Test {
        dir: tempfile::TempDir,
        fake: FakeServiced,
        controller: Controller,
    }

    impl Test {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let (fake, client) = FakeServiced::start(dir.path(), &dir.path().join("root")).await;
            fake.put(Layer::Image, KUBELET, IMAGE_KUBELET);
            let controller = Self::controller(dir.path(), client);
            Self {
                dir,
                fake,
                controller,
            }
        }

        fn controller(dir: &Path, client: ServicedClient<Channel>) -> Controller {
            Controller::new(client, dir.join("root"), dir.join("state.json"))
        }

        fn exists(&self, path: &str) -> bool {
            self.dir.path().join("root").join(path).exists()
        }
    }

    /// One configuration, its CA generated once.
    static ENABLED: LazyLock<kubelet::Kubelet> = LazyLock::new(|| config(&static_pods()).into());

    fn enabled(node_name: &str) -> Request<kubelet::Configuration> {
        Request::new(kubelet::Configuration {
            kubelet: Some(ENABLED.clone()),
            node_name: node_name.into(),
        })
    }

    fn disabled() -> Request<kubelet::Configuration> {
        Request::new(kubelet::Configuration {
            kubelet: None,
            node_name: "node-1".into(),
        })
    }

    fn kubelet(call: fn(String) -> Call) -> Call {
        call(KUBELET.into())
    }

    #[tokio::test]
    async fn enables_kubelet_with_its_files() {
        let test = Test::new().await;
        test.controller.configure(enabled("node-1")).await.unwrap();
        assert_eq!(test.fake.take_calls(), [Call::Reload, kubelet(Call::Start)]);
        for path in [
            "run/kubelet/config.json",
            "run/kubelet/bootstrap-kubeconfig",
            "var/lib/kubelet/manifests/web.yaml",
        ] {
            assert!(test.exists(path), "{path}");
        }

        // The drop-in merged over the image's service.
        let root = test.dir.path().join("root");
        let (services, errors) = definition::load(&[
            (Layer::Image, &Layer::Image.dir_in(&root)),
            (Layer::Runtime, &Layer::Runtime.dir_in(&root)),
        ]);
        assert!(errors.is_empty(), "{errors:?}");
        let service = &services[KUBELET].service;
        assert!(service.enabled);
        assert_eq!(service.exec.program().as_str(), "/usr/bin/kubelet");
        assert_eq!(service.exec.args()[0], "--config=/run/kubelet/config.json");
        assert!(
            service
                .exec
                .args()
                .contains(&"--hostname-override=node-1".to_owned())
        );
        assert_eq!(
            service.requires[0].as_str(),
            "containerd",
            "kept from the image"
        );
    }

    #[tokio::test]
    async fn restarts_kubelet_when_its_configuration_changes() {
        let test = Test::new().await;
        test.controller.configure(enabled("node-1")).await.unwrap();
        test.fake.take_calls();
        test.controller.configure(enabled("node-1")).await.unwrap();
        assert_eq!(test.fake.take_calls(), [Call::Reload, kubelet(Call::Start)]);
        test.controller.configure(enabled("node-2")).await.unwrap();
        assert_eq!(
            test.fake.take_calls(),
            [Call::Reload, kubelet(Call::Restart)]
        );
    }

    #[tokio::test]
    async fn disables_kubelet() {
        let test = Test::new().await;
        test.controller.configure(enabled("node-1")).await.unwrap();
        test.fake.take_calls();
        test.controller.configure(disabled()).await.unwrap();
        assert_eq!(test.fake.take_calls(), [Call::Reload, kubelet(Call::Stop)]);
        assert_eq!(test.fake.file(Layer::Runtime, KUBELET), None);
        test.controller.configure(disabled()).await.unwrap();
        assert_eq!(test.fake.take_calls(), [Call::Reload, kubelet(Call::Stop)]);
    }

    #[tokio::test]
    async fn refuses_invalid_configurations() {
        let test = Test::new().await;
        let mut bad_server = enabled("node-1");
        if let Some(kubelet) = &mut bad_server.get_mut().kubelet {
            kubelet.api_server = "http://k8s".into();
        }
        for (request, field) in [
            (enabled("Not a hostname"), "node_name"),
            (bad_server, "kubelet.api_server"),
        ] {
            let status = test.controller.configure(request).await.unwrap_err();
            assert_eq!(status.code(), Code::InvalidArgument);
            assert!(status.message().starts_with(field), "{}", status.message());
        }
        assert_eq!(test.fake.take_calls(), []);
        assert!(!test.dir.path().join("state.json").exists());
        assert!(!test.exists("run/kubelet"));
    }

    #[tokio::test]
    async fn a_restarted_controller_applies_its_state_again() {
        let test = Test::new().await;
        test.controller.configure(enabled("node-1")).await.unwrap();
        let configured = test.controller.current.lock().await.clone();
        fs::remove_dir_all(test.dir.path().join("root/run/kubelet")).unwrap();

        let other = test.dir.path().join("restarted");
        fs::create_dir(&other).unwrap();
        let (fake, client) = FakeServiced::start(&other, &test.dir.path().join("root")).await;
        let restarted = Test::controller(test.dir.path(), client);
        restarted.restore().await;
        assert!(configured.is_some());
        assert_eq!(*restarted.current.lock().await, configured);
        assert_eq!(fake.take_calls(), [Call::Reload, kubelet(Call::Start)]);
        assert!(test.exists("run/kubelet/config.json"));
    }
}

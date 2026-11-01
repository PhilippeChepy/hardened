//! Configuring the controllers through their APIs, from the settings.
//!
//! In order: network-controller (the resolver), storage-controller (`/var` is set up when the
//! call returns, so containerd can start), time-controller, workload-controller, then
//! kubelet-controller on Kubernetes targets. network-controller and storage-controller are
//! essential: the machine is of no use without them. machine-apiproxy is configured apart, once
//! the machine's API serves ([`configure_api_proxy`]).

use anyhow::Context;
use controllers_helpers::Hostname;
use kubelet_controller::kubelet;
use kubelet_controller::kubelet::kubelet_controller_client::KubeletControllerClient;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::client;
use libserviced::definition;
use libserviced::definition::Layer;
use libserviced::definition::ServiceName;
use machine_apiproxy::ApiConfig;
use machine_apiproxy::apiproxy;
use machine_apiproxy::apiproxy::machine_api_proxy_client::MachineApiProxyClient;
use machine_controller::Settings;
use network_controller::network;
use network_controller::network::network_controller_client::NetworkControllerClient;
use storage_controller::storage;
use storage_controller::storage::storage_controller_client::StorageControllerClient;
use time_controller::TimeConfig;
use time_controller::time;
use time_controller::time::time_controller_client::TimeControllerClient;
use tonic::Response;
use tonic::Status;
use tracing::error;
use tracing::info;
use workload_controller::workload;
use workload_controller::workload::workload_controller_client::WorkloadControllerClient;

use crate::controllers::Controllers;
use crate::time_servers;

/// machine-apiproxy's service, which its image file leaves disabled.
const API_PROXY_SERVICE: &str = "machine-apiproxy";
const API_PROXY: ServiceName = ServiceName::from_static(API_PROXY_SERVICE);

/// Configures the controllers for `settings`, on the machine named `hostname`, whose DHCP offered
/// `dhcp_time_servers`.
///
/// # Errors
///
/// When network-controller or storage-controller cannot be configured; the others' failures are
/// logged.
pub async fn configure(
    controllers: &Controllers,
    settings: &Settings,
    hostname: &Hostname,
    dhcp_time_servers: &[String],
) -> anyhow::Result<()> {
    let mut network = NetworkControllerClient::new(controllers.network.channel());
    network
        .configure(network::Configuration::from(settings.dns.clone()))
        .await
        .context("configuring network-controller")?;
    info!("network-controller configured");

    let mut storage = StorageControllerClient::new(controllers.storage.channel());
    storage
        .configure(storage::Configuration::from(
            settings.hardened.storage.clone(),
        ))
        .await
        .context("configuring storage-controller")?;
    info!("storage-controller configured: /var is set up");

    configure_time(
        controllers,
        time_servers::choose(settings, dhcp_time_servers),
    )
    .await;

    // Whether kubelet runs or not: workloads are in their own containerd namespace.
    let workloads = workload::Configuration::from(settings.hardened.containers.clone());
    let configured = WorkloadControllerClient::new(controllers.workload.channel())
        .configure(workloads)
        .await;
    log_outcome(
        configured,
        "workload-controller",
        "the workloads of user-data do not run",
    );

    if controllers.kubelet.exists() {
        let configuration = kubelet::Configuration {
            kubelet: settings
                .kubernetes
                .as_ref()
                .map(|config| kubelet::Kubelet::from(config.clone())),
            node_name: hostname.to_string(),
        };
        let configured = KubeletControllerClient::new(controllers.kubelet.channel())
            .configure(configuration)
            .await;
        log_outcome(configured, "kubelet-controller", "kubelet does not run");
    }
    Ok(())
}

/// Configures time-controller with `time`; returns whether it was.
pub async fn configure_time(controllers: &Controllers, time: TimeConfig) -> bool {
    info!(
        source = ?time.source,
        servers = ?time.servers,
        origin = ?time.origin,
        "time sources chosen"
    );
    let configured = TimeControllerClient::new(controllers.time.channel())
        .configure(time::Configuration::from(time))
        .await;
    let ok = configured.is_ok();
    log_outcome(configured, "time-controller", "the clock may drift");
    ok
}

/// Logs how configuring a controller the machine works without went, and the `consequence` of a
/// failure.
fn log_outcome(configured: Result<Response<()>, Status>, controller: &str, consequence: &str) {
    match configured {
        Ok(_) => info!(controller, "controller configured"),
        Err(status) => error!(
            "cannot configure {controller}, {consequence}: {}",
            status.message()
        ),
    }
}

/// Enables machine-apiproxy with a drop-in in serviced's runtime layer (serviced then creates its
/// socket), and configures it with `config`.
///
/// # Errors
///
/// When it cannot be enabled or configured.
pub async fn configure_api_proxy(
    controllers: &Controllers,
    config: &ApiConfig,
) -> anyhow::Result<()> {
    let name = API_PROXY;
    definition::write_service_file(&controllers.root, Layer::Runtime, &name, "enabled = true\n")
        .context("enabling machine-apiproxy")?;
    let mut serviced = ServicedClient::new(controllers.serviced.channel());
    client::reload(&mut serviced)
        .await
        .context("enabling machine-apiproxy")?;
    let mut apiproxy = MachineApiProxyClient::new(controllers.apiproxy.channel());
    apiproxy
        .configure(apiproxy::Configuration::from(config.clone()))
        .await
        .context("configuring machine-apiproxy")?;
    info!(listen = %config.listen, "machine-apiproxy configured");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use controllers_helpers::base64_text;
    use controllers_helpers::testing;
    use machine_controller::UserData;

    use super::*;
    use crate::fake_controllers::FakeControllers;

    fn hostname() -> Hostname {
        "node-1".parse().unwrap()
    }

    fn settings(document: &str) -> Settings {
        UserData::parse(document.as_bytes()).unwrap().settings
    }

    #[tokio::test]
    async fn configures_the_controllers_in_order() {
        let fakes = FakeControllers::start().await;
        let settings = settings(
            "[settings.dns]\nname-servers = [\"192.0.2.53\"]\n\
             [settings.hardened.storage]\nencryption = \"tpm\"\n\
             [settings.hardened.containers.web]\nimage = \"nginx\"\n",
        );
        configure(
            &fakes.controllers,
            &settings,
            &hostname(),
            &["10.0.0.4".to_owned()],
        )
        .await
        .unwrap();
        assert_eq!(
            fakes.calls(),
            [
                "network-controller Configure name_servers=[\"192.0.2.53\"]",
                "storage-controller Configure encryption=Tpm",
                "time-controller Configure servers=[\"10.0.0.4\"] origin=Dhcp",
                "workload-controller Configure workloads=[\"web\"]",
                "kubelet-controller Configure kubelet=false node_name=node-1",
            ]
        );
    }

    #[tokio::test]
    async fn workloads_run_beside_kubelet() {
        let (certificate, _) = testing::certificate_and_key();
        let certificate = base64_text::encode(certificate);
        let fakes = FakeControllers::start().await;
        let settings = settings(&format!(
            "[settings.kubernetes]\n\
             api-server = \"https://k8s.example.com:6443\"\n\
             cluster-certificate = \"{certificate}\"\n\
             bootstrap-token = \"abcdef.0123456789abcdef\"\n\
             [settings.hardened.containers.web]\nimage = \"nginx\"\n"
        ));
        configure(&fakes.controllers, &settings, &hostname(), &[])
            .await
            .unwrap();
        let calls = fakes.calls();
        assert_eq!(
            calls[3..],
            [
                "workload-controller Configure workloads=[\"web\"]",
                "kubelet-controller Configure kubelet=true node_name=node-1",
            ]
        );
    }

    #[tokio::test]
    async fn without_kubelet_controller() {
        let fakes = FakeControllers::start().await;
        fakes.stop("kubelet-controller");
        configure(&fakes.controllers, &Settings::default(), &hostname(), &[])
            .await
            .unwrap();
        let calls = fakes.calls();
        assert!(
            calls.last().unwrap().starts_with("workload-controller"),
            "{calls:?}"
        );
    }

    #[tokio::test]
    async fn network_and_storage_are_essential() {
        let fakes = FakeControllers::start().await;
        fakes.stop("storage-controller");
        assert!(
            configure(&fakes.controllers, &Settings::default(), &hostname(), &[])
                .await
                .is_err()
        );
        assert_eq!(fakes.calls().len(), 1, "nothing after storage-controller");
    }

    #[tokio::test]
    async fn the_others_degrade() {
        let fakes = FakeControllers::start().await;
        fakes.stop("time-controller");
        fakes.stop("workload-controller");
        configure(&fakes.controllers, &Settings::default(), &hostname(), &[])
            .await
            .unwrap();
        assert_eq!(fakes.calls().len(), 3, "network, storage and kubelet");
    }

    #[tokio::test]
    async fn enables_then_configures_machine_apiproxy() {
        let fakes = FakeControllers::start().await;
        let settings = settings(&crate::fake_controllers::api_user_data());
        let config = settings.hardened.api.as_ref().unwrap();
        let name = API_PROXY_SERVICE.parse().unwrap();
        let image = Layer::Image.dir_in(fakes.dir());
        fs::create_dir_all(&image).unwrap();
        fs::write(
            definition::service_file(&image, &name),
            "enabled = false\nexec = [\"/usr/bin/machine-apiproxy\"]\n",
        )
        .unwrap();
        configure_api_proxy(&fakes.controllers, config)
            .await
            .unwrap();
        assert_eq!(
            fakes.calls(),
            [
                "serviced Reload",
                "machine-apiproxy Configure listen=0.0.0.0:7443",
            ]
        );
        let file = definition::service_file(&Layer::Runtime.dir_in(fakes.dir()), &name);
        assert_eq!(fs::read_to_string(file).unwrap(), "enabled = true\n");
    }
}

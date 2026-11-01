//! The instance's setup, before the controllers are configured: the network as network-controller
//! configured it, the platform's metadata and user-data, then the hostname and machine ID,
//! sysctls, kernel modules and containerd's configuration. serviced has already pinned kernel
//! files to the root (LoadPin) and set the hardened sysctls.
//!
//! Nothing here fails: what cannot be done is logged and worked around.

use machine_controller::Settings;
use machine_controller::UserData;
use network_controller::network;
use network_controller::network::network_controller_client::NetworkControllerClient;
use tracing::error;
use tracing::info;
use tracing::warn;

use crate::containerd;
use crate::controllers::Controllers;
use crate::hostnames;
use crate::hosts;
use crate::kmod;
use crate::machine_id::MachineId;
use crate::machine_identity::MachineIdentity;
use crate::metadata::Metadata;
use crate::metadata::Platform;
use crate::sysctl;

/// What the setup found.
#[derive(Debug)]
pub struct Setup {
    pub identity: MachineIdentity,
    /// The settings of user-data; the defaults without valid user-data.
    pub settings: Settings,
    /// The time servers DHCP offered.
    pub dhcp_time_servers: Vec<String>,
}

/// Sets the instance up.
pub async fn run(controllers: &Controllers) -> Setup {
    let network = network_state(controllers).await;
    let platform = Platform::detect();
    match platform {
        Some(platform) => info!(%platform, "platform detected"),
        None => warn!("unknown platform: no metadata source"),
    }
    let Metadata {
        instance_id,
        hostname: platform_hostname,
        user_data,
    } = fetch_metadata(platform).await;
    let settings = parse(user_data.as_deref());

    let hostname = settings
        .network
        .hostname
        .clone()
        .or(platform_hostname)
        .or_else(|| {
            network
                .dhcp_hostname
                .as_deref()
                .and_then(hostnames::sanitize)
        })
        .unwrap_or_else(|| hostnames::from_instance_id(instance_id.as_deref()));
    if let Err(e) = hosts::apply(&hostname) {
        error!(%hostname, error = format!("{e:#}"), "cannot apply the hostname");
    }
    match MachineId::new(instance_id.as_deref()).and_then(MachineId::write) {
        Ok(()) if instance_id.is_none() => warn!("no instance ID: the machine ID is this boot's"),
        Ok(()) => {}
        Err(e) => error!(error = format!("{e:#}"), "cannot write the machine ID"),
    }
    info!(
        %hostname,
        instance_id = instance_id.as_deref().unwrap_or("none"),
        "identity configured"
    );

    if settings.kubernetes.is_some() {
        if controllers.kubelet.exists() {
            sysctl::apply_kubernetes_defaults();
        } else {
            error!("settings.kubernetes is set, but this image has no kubelet");
        }
    }
    sysctl::apply(&settings.kernel.sysctl);
    let modules = settings.kernel.modules.clone();
    if let Err(e) = tokio::task::spawn_blocking(move || kmod::load(&modules)).await {
        error!(error = %e, "cannot load the kernel modules");
    }
    containerd::configure(&settings.container_registry);

    let identity = MachineIdentity::read(platform, instance_id, hostname);
    info!(
        os_version = identity.os_version,
        kernel = identity.kernel,
        "instance set up"
    );
    Setup {
        identity,
        settings,
        dhcp_time_servers: network.ntp_servers,
    }
}

/// The settings of `user_data`; the defaults when there is none, or it is invalid.
#[must_use]
fn parse(user_data: Option<&[u8]>) -> Settings {
    let Some(raw) = user_data else {
        info!("no user-data");
        return Settings::default();
    };
    match UserData::parse(raw) {
        Ok(user_data) => user_data.settings,
        Err(e) => {
            error!(error = %e, "ignoring invalid user-data");
            Settings::default()
        }
    }
}

/// What DHCP offered, as network-controller tells; nothing if it cannot.
async fn network_state(controllers: &Controllers) -> network::State {
    let state = NetworkControllerClient::new(controllers.network.channel())
        .get_state(())
        .await;
    match state {
        Ok(state) => state.into_inner(),
        Err(status) => {
            error!(
                "cannot read network-controller's state: {}",
                status.message()
            );
            network::State::default()
        }
    }
}

/// The platform's metadata and user-data; none when it is unknown or does not answer.
async fn fetch_metadata(platform: Option<Platform>) -> Metadata {
    let Some(platform) = platform else {
        return Metadata::default();
    };
    platform.fetch().await.unwrap_or_else(|e| {
        error!(%platform, error = format!("{e:#}"), "fetching metadata failed");
        Metadata::default()
    })
}

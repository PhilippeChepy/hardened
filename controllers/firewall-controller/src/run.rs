//! The controller: applies the kept configuration, then serves its API.

use std::convert::Infallible;
use std::future;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use firewall_controller::FirewallConfig;
use firewall_controller::firewall::firewall_controller_server::FirewallControllerServer;
use libserviced::activation::ActivatedSocket;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::notify;
use tonic::transport::Channel;
use tonic::transport::Server;

use crate::firewall_service::FirewallService;
use crate::firewall_service::Nftables;
use crate::kmsg;
use crate::options::Options;
use crate::persisted_state::PersistedState;

/// What applies at start.
#[derive(Debug, PartialEq, Eq)]
struct Initial {
    /// The configuration kept, else the default.
    config: FirewallConfig,
    /// The system's default (its file), else the built-in one.
    default: FirewallConfig,
    /// Why a file was ignored, if one was.
    notice: Option<String>,
}

/// The configuration to apply at start: the one kept in `state_file`, else the default, the
/// system's from `default_file` or the built-in one (on, nothing let in); with a notice when a
/// file was invalid.
fn initial_config(state_file: &Path, default_file: &Path) -> Initial {
    let mut notices = Vec::new();
    let default = match PersistedState::load(default_file) {
        Ok(Some(seed)) => seed.config,
        Ok(None) => FirewallConfig::default(),
        Err(error) => {
            let error = format!("{error:#}");
            tracing::error!(
                error,
                "ignoring the system's default: the built-in one applies"
            );
            notices.push(format!("the system's default was ignored: {error}"));
            FirewallConfig::default()
        }
    };
    let config = match PersistedState::load(state_file) {
        Ok(Some(persisted)) => persisted.config,
        Ok(None) => default.clone(),
        Err(error) => {
            let error = format!("{error:#}");
            tracing::error!(
                error,
                "ignoring the kept configuration: the default applies"
            );
            notices.push(format!("the kept configuration was ignored: {error}"));
            default.clone()
        }
    };
    Initial {
        config,
        default,
        notice: (!notices.is_empty()).then(|| notices.join("; ")),
    }
}

/// Applies the configuration kept in `options.state_file` (the default without, or when the
/// kernel refuses it), reports ready to serviced (the network comes up after it), then serves
/// `hardened.firewall.v1` on `api` to the callers `serviced` identifies. Returns only on an
/// error: one applying the firewall at all, before reporting ready (serviced restarts it; the
/// network fails closed, waiting). A kernel without nf_tables is ready: nothing can be filtered,
/// the status says so.
pub async fn run(
    options: Options,
    api: ActivatedSocket,
    serviced: ServicedClient<Channel>,
) -> anyhow::Result<Infallible> {
    let Initial {
        config,
        default,
        notice,
    } = initial_config(&options.state_file, &options.default_file);
    let recent = Arc::default();
    let service = Arc::new(FirewallService::new(
        config.clone(),
        default,
        notice,
        options.state_file,
        Arc::new(Nftables),
        Arc::clone(&recent),
    ));
    // Not ready, the network waiting, unless applied or the kernel without nf_tables.
    service
        .start()
        .await
        .context("the firewall cannot be applied: the network stays down")?;
    let status = service.status().await;
    match status.error {
        None if config.enabled => tracing::info!("firewall applied"),
        None => tracing::info!("firewall off"),
        Some(error) => tracing::error!(error, "the firewall is not applied as kept"),
    }
    if let Err(error) = notify::ready() {
        tracing::warn!(%error, "cannot notify serviced of the readiness");
    }
    // Once the network may come up: the log's backlog is read meanwhile.
    kmsg::spawn(recent);
    let router = Server::builder().add_service(FirewallControllerServer::from_arc(service));
    libserviced::authorization::serve(router, api, serviced, future::pending())
        .await
        .context("serving the API")?;
    Err(anyhow::anyhow!("the API stopped serving"))
}

#[cfg(test)]
mod tests {
    use firewall_controller::Ruleset;

    use super::*;

    #[test]
    fn the_first_boot_applies_the_default() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("config.json");
        let seed = dir.path().join("default.json");
        let initial = initial_config(&state, &seed);
        assert_eq!(initial.default, FirewallConfig::default());
        assert_eq!(initial.config, initial.default);
        let config = initial.config;
        assert_eq!((config.enabled, initial.notice), (true, None));
        let ruleset = Ruleset::of(&config).unwrap();
        let comments: Vec<_> = ruleset
            .rules()
            .map(|(_, rule)| rule.comment.as_str())
            .collect();
        assert_eq!(
            comments,
            [
                "loopback",
                "established",
                "invalid",
                "icmpv6",
                "icmp",
                "dhcp",
                "dhcpv6",
                "log",
                "drop"
            ]
        );

        std::fs::write(&state, "{").unwrap();
        let initial = initial_config(&state, &seed);
        assert!(initial.config.enabled, "an invalid file: the default, on");
        assert!(
            initial
                .notice
                .unwrap()
                .starts_with("the kept configuration was ignored")
        );
    }

    #[test]
    fn the_system_s_default_applies_when_none_is_kept() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("config.json");
        let seed = dir.path().join("default.json");
        std::fs::write(&seed, r#"{"config": {"enabled": false}}"#).unwrap();
        let initial = initial_config(&state, &seed);
        assert!(!initial.default.enabled && !initial.config.enabled);
        assert_eq!(initial.notice, None);

        // A kept one wins over it.
        let kept = PersistedState {
            config: FirewallConfig::default(),
        };
        kept.save(&state).unwrap();
        let initial = initial_config(&state, &seed);
        assert!(initial.config.enabled && !initial.default.enabled);

        // An invalid default: the built-in one, said.
        std::fs::remove_file(&state).unwrap();
        std::fs::write(&seed, "{}").unwrap();
        let initial = initial_config(&state, &seed);
        assert_eq!(initial.config, FirewallConfig::default());
        assert!(
            initial
                .notice
                .unwrap()
                .starts_with("the system's default was ignored")
        );
    }
}

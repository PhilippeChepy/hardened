//! Following DHCP: time-controller is configured again whenever the time servers DHCP offers
//! change what it synchronizes with.

use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use machine_controller::Settings;
use network_controller::network::network_controller_client::NetworkControllerClient;
use time_controller::TimeConfig;
use tracing::warn;

use crate::configuration;
use crate::controllers::Controllers;
use crate::time_servers;

/// How long to wait before watching again, once network-controller's stream fails or ends.
const RETRY: Duration = Duration::from_secs(5);

/// Watches what DHCP offers, and configures time-controller whenever [`time_servers::choose`]
/// chooses differently for `settings`. Its first state is compared with nothing: time-controller
/// is configured again with the same choice after a restart, which changes nothing.
pub async fn follow(controllers: Arc<Controllers>, settings: Settings) -> Infallible {
    let mut configured: Option<TimeConfig> = None;
    loop {
        let watched = NetworkControllerClient::new(controllers.network.channel())
            .watch_state(())
            .await;
        match watched {
            Ok(states) => {
                let mut states = states.into_inner();
                loop {
                    match states.message().await {
                        Ok(Some(state)) => {
                            let chosen = time_servers::choose(&settings, &state.ntp_servers);
                            if configured.as_ref() != Some(&chosen) {
                                let ok =
                                    configuration::configure_time(&controllers, chosen.clone())
                                        .await;
                                configured = ok.then_some(chosen);
                            }
                        }
                        Ok(None) => {
                            warn!("network-controller's state stream ended");
                            break;
                        }
                        Err(status) => {
                            warn!("watching network-controller's state: {}", status.message());
                            break;
                        }
                    }
                }
            }
            Err(status) => warn!(
                "cannot watch network-controller's state: {}",
                status.message()
            ),
        }
        tokio::time::sleep(RETRY).await;
    }
}

#[cfg(test)]
mod tests {
    use network_controller::network;

    use super::*;
    use crate::fake_controllers::FakeControllers;

    fn offer(fakes: &FakeControllers, ntp_servers: &[&str]) {
        fakes.dhcp.send_replace(network::State {
            dhcp_hostname: None,
            ntp_servers: ntp_servers
                .iter()
                .map(|&server| server.to_owned())
                .collect(),
        });
    }

    async fn next_calls(fakes: &FakeControllers) -> Vec<String> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let calls = fakes.calls();
                if !calls.is_empty() {
                    return calls;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn reconfigures_time_controller_when_dhcp_changes_its_choice() {
        let fakes = FakeControllers::start().await;
        offer(&fakes, &["10.0.0.4"]);
        tokio::spawn(follow(fakes.controllers.clone(), Settings::default()));
        assert_eq!(
            next_calls(&fakes).await,
            ["time-controller Configure servers=[\"10.0.0.4\"] origin=Dhcp"]
        );

        offer(&fakes, &["10.0.0.4"]);
        offer(&fakes, &["10.0.0.6", "not a server"]);
        assert_eq!(
            next_calls(&fakes).await,
            ["time-controller Configure servers=[\"10.0.0.6\"] origin=Dhcp"],
            "the same choice again is not sent"
        );

        offer(&fakes, &[]);
        assert_eq!(
            next_calls(&fakes).await,
            ["time-controller Configure servers=[\"pool.ntp.org\"] origin=Default"]
        );
    }

    #[tokio::test]
    async fn the_settings_win_over_dhcp() {
        let fakes = FakeControllers::start().await;
        let mut settings = Settings::default();
        settings.ntp.time_servers = vec!["time.example.com".parse().unwrap()];
        offer(&fakes, &["10.0.0.4"]);
        tokio::spawn(follow(fakes.controllers.clone(), settings));
        assert_eq!(
            next_calls(&fakes).await,
            ["time-controller Configure servers=[\"time.example.com\"] origin=Settings"]
        );
        offer(&fakes, &["10.0.0.6"]);
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(fakes.calls().is_empty(), "the choice is the same");
    }
}

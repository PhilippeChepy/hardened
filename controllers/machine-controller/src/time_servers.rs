//! What time-controller synchronizes the clock with.

use controllers_helpers::Hostname;
use controllers_helpers::NonEmpty;
use machine_controller::Settings;
use time_controller::TimeConfig;
use time_controller::TimeOrigin;
use time_controller::TimeServer;
use tracing::warn;

const DEFAULT_SERVER: Hostname = Hostname::from_static("pool.ntp.org");

/// `settings.hardened.time.source`, with `settings.ntp.time-servers`, else the servers DHCP
/// offered (option 42), else [`DEFAULT_SERVER`].
#[must_use]
pub fn choose(settings: &Settings, dhcp: &[String]) -> TimeConfig {
    let source = settings.hardened.time.source;
    if let Some(servers) = NonEmpty::from_vec(settings.ntp.time_servers.clone()) {
        return TimeConfig {
            servers,
            origin: TimeOrigin::Settings,
            source,
        };
    }
    let dhcp: Vec<TimeServer> = dhcp
        .iter()
        .filter_map(|server| match server.parse() {
            Ok(server) => Some(server),
            Err(e) => {
                warn!(server, "ignoring a time server of DHCP: {e}");
                None
            }
        })
        .collect();
    if let Some(servers) = NonEmpty::from_vec(dhcp) {
        return TimeConfig {
            servers,
            origin: TimeOrigin::Dhcp,
            source,
        };
    }
    TimeConfig {
        servers: NonEmpty::new(TimeServer::Host(DEFAULT_SERVER)),
        origin: TimeOrigin::Default,
        source,
    }
}

#[cfg(test)]
mod tests {
    use time_controller::TimeSource;

    use super::*;

    fn servers(config: &TimeConfig) -> Vec<String> {
        config.servers.iter().map(TimeServer::to_string).collect()
    }

    #[test]
    fn settings_then_dhcp_then_the_default() {
        let dhcp = ["10.0.0.4".to_owned(), "10.0.0.5".to_owned()];
        let mut configured = Settings::default();
        configured.ntp.time_servers = vec!["time.example.com".parse().unwrap()];
        configured.hardened.time.source = TimeSource::Ntp;
        let chosen = choose(&configured, &dhcp);
        assert_eq!(chosen.origin, TimeOrigin::Settings);
        assert_eq!(chosen.source, TimeSource::Ntp);
        assert_eq!(servers(&chosen), ["time.example.com"]);

        let chosen = choose(&Settings::default(), &dhcp);
        assert_eq!(chosen.origin, TimeOrigin::Dhcp);
        assert_eq!(servers(&chosen), ["10.0.0.4", "10.0.0.5"]);

        let chosen = choose(&Settings::default(), &[]);
        assert_eq!(chosen.origin, TimeOrigin::Default);
        assert_eq!(servers(&chosen), ["pool.ntp.org"]);
    }

    #[test]
    fn invalid_dhcp_servers_are_skipped() {
        let chosen = choose(&Settings::default(), &["not a server".to_owned()]);
        assert_eq!(chosen.origin, TimeOrigin::Default);
        let dhcp = ["not a server".to_owned(), "10.0.0.4".to_owned()];
        assert_eq!(servers(&choose(&Settings::default(), &dhcp)), ["10.0.0.4"]);
    }
}

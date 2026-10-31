//! The servers time-controller synchronizes with.

use controllers_helpers::Hostname;
use controllers_helpers::NonEmpty;
use machine_controller::NtpSettings;
use time_controller::TimeConfig;
use time_controller::TimeOrigin;
use time_controller::TimeServer;
use tracing::warn;

const DEFAULT_SERVER: Hostname = Hostname::from_static("pool.ntp.org");

/// `settings.ntp.time-servers`, else the servers DHCP offered (option 42), else
/// [`DEFAULT_SERVER`].
#[must_use]
pub fn choose(settings: &NtpSettings, dhcp: &[String]) -> TimeConfig {
    if let Some(servers) = NonEmpty::from_vec(settings.time_servers.clone()) {
        return TimeConfig {
            servers,
            origin: TimeOrigin::Settings,
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
        };
    }
    TimeConfig {
        servers: NonEmpty::new(TimeServer::Host(DEFAULT_SERVER)),
        origin: TimeOrigin::Default,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn servers(config: &TimeConfig) -> Vec<String> {
        config.servers.iter().map(TimeServer::to_string).collect()
    }

    #[test]
    fn settings_then_dhcp_then_the_default() {
        let dhcp = ["10.0.0.4".to_owned(), "10.0.0.5".to_owned()];
        let configured = NtpSettings {
            time_servers: vec!["time.example.com".parse().unwrap()],
        };
        let chosen = choose(&configured, &dhcp);
        assert_eq!(chosen.origin, TimeOrigin::Settings);
        assert_eq!(servers(&chosen), ["time.example.com"]);

        let chosen = choose(&NtpSettings::default(), &dhcp);
        assert_eq!(chosen.origin, TimeOrigin::Dhcp);
        assert_eq!(servers(&chosen), ["10.0.0.4", "10.0.0.5"]);

        let chosen = choose(&NtpSettings::default(), &[]);
        assert_eq!(chosen.origin, TimeOrigin::Default);
        assert_eq!(servers(&chosen), ["pool.ntp.org"]);
    }

    #[test]
    fn invalid_dhcp_servers_are_skipped() {
        let chosen = choose(&NtpSettings::default(), &["not a server".to_owned()]);
        assert_eq!(chosen.origin, TimeOrigin::Default);
        let dhcp = ["not a server".to_owned(), "10.0.0.4".to_owned()];
        assert_eq!(
            servers(&choose(&NtpSettings::default(), &dhcp)),
            ["10.0.0.4"]
        );
    }
}

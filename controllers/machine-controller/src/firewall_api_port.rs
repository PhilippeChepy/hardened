//! The firewall machine-controller configures: the settings', always letting the machine's API
//! in, so that no firewall setting can lock out the machine's operators.

use anyhow::Context;
use firewall_controller::Allowed;
use firewall_controller::AllowedList;
use firewall_controller::FirewallConfig;
use firewall_controller::Port;
use firewall_controller::Ports;
use firewall_controller::Protocol;
use machine_apiproxy::ApiConfig;

/// `config`, also letting in TCP to `api`'s port when the API is served.
///
/// # Errors
///
/// When the allowed list is full: the API cannot be let in.
pub fn with_api_allowed(
    config: &FirewallConfig,
    api: Option<&ApiConfig>,
) -> anyhow::Result<FirewallConfig> {
    let mut config = config.clone();
    let Some(api) = api else {
        return Ok(config);
    };
    let port = Port::try_from(u32::from(api.listen.port()))
        .context("settings.hardened.api.listen has no port")?;
    let allowed = Allowed::Ports(Ports::one(Protocol::Tcp, port));
    if config.allowed_inbound.items().iter().any(|item| {
        item.ports()
            .iter()
            .any(|ports| ports.covers(Protocol::Tcp, port))
    }) {
        return Ok(config);
    }
    let mut items = config.allowed_inbound.items().to_vec();
    items.push(allowed);
    config.allowed_inbound = AllowedList::try_from(items)
        .context("settings.hardened.firewall.allowed-inbound: letting the API in")?;
    Ok(config)
}

#[cfg(test)]
mod tests {
    use controllers_helpers::base64_text;
    use controllers_helpers::testing;

    use super::*;

    fn api(listen: &str) -> ApiConfig {
        let (certificate, key) = testing::certificate_and_key();
        let certificate = base64_text::encode(&certificate);
        let key = base64_text::encode(&key);
        toml::from_str(&format!(
            "listen = \"{listen}\"\nclient-ca = \"{certificate}\"\n\
             certificate = \"{certificate}\"\nprivate-key = \"{key}\"\n"
        ))
        .unwrap()
    }

    fn inbound(config: &FirewallConfig) -> Vec<String> {
        let items = config.allowed_inbound.items().iter();
        items.map(ToString::to_string).collect()
    }

    #[test]
    fn lets_the_api_in() {
        let config = FirewallConfig::default();
        let with = with_api_allowed(&config, Some(&api("0.0.0.0:7443"))).unwrap();
        assert_eq!(inbound(&with), ["7443/tcp"]);
        assert_eq!(with_api_allowed(&config, None).unwrap(), config);
    }

    #[test]
    fn keeps_a_range_already_letting_it_in() {
        let config = FirewallConfig {
            allowed_inbound: AllowedList::try_from(vec!["7000-8000/tcp".parse().unwrap()]).unwrap(),
            ..FirewallConfig::default()
        };
        let with = with_api_allowed(&config, Some(&api("[::]:7443"))).unwrap();
        assert_eq!(inbound(&with), ["7000-8000/tcp"]);
    }
}

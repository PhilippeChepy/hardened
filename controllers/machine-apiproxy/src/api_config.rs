//! `[settings.hardened.api]`.

use std::net::SocketAddr;

use controllers_helpers::{Certificates, PrivateKey};
use serde::{Deserialize, Serialize};

/// `[settings.hardened.api]`: the API, served by machine-apiproxy, which runs when the table is
/// there. It has its whole TLS identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ApiConfig {
    /// The address machine-apiproxy serves on.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// The CA client certificates must chain to.
    pub client_ca: Certificates,
    /// The server's certificate chain.
    pub certificate: Certificates,
    /// The key of the server's certificate.
    pub private_key: PrivateKey,
}

#[must_use]
fn default_listen() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 7443))
}

#[cfg(test)]
mod tests {
    use controllers_helpers::base64_text;
    use controllers_helpers::testing;

    use super::*;

    #[test]
    fn round_trips_with_the_private_key() {
        let (certificate, key) = testing::certificate_and_key();
        let encoded = base64_text::encode(&certificate);
        let document = format!(
            "client-ca = \"{encoded}\"\ncertificate = \"{encoded}\"\nprivate-key = \"{}\"\n",
            base64_text::encode(key)
        );
        let api: ApiConfig = toml::from_str(&document).unwrap();
        assert_eq!(api.listen, default_listen());
        let text = toml::to_string(&api).unwrap();
        assert!(
            text.contains(&format!("certificate = \"{encoded}\"")),
            "certificates serialize back to base64: {text}"
        );
        assert_eq!(toml::from_str::<ApiConfig>(&text).unwrap(), api);
        assert!(!format!("{api:?}").contains("PRIVATE KEY"));
    }

    #[test]
    fn requires_the_tls_identity() {
        let (certificate, _) = testing::certificate_and_key();
        let encoded = base64_text::encode(&certificate);
        let document = format!("client-ca = \"{encoded}\"\ncertificate = \"{encoded}\"\n");
        assert!(toml::from_str::<ApiConfig>(&document).is_err());
    }
}

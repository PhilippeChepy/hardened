//! `settings.hardened.api` as machine-apiproxy's configuration.

use std::net::SocketAddr;

use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::FieldResult;
use controllers_helpers::{Certificates, InvalidMessage, PrivateKey};

use crate::ApiConfig;
use crate::apiproxy;

/// PEM text, the private key included.
impl From<ApiConfig> for apiproxy::Configuration {
    fn from(config: ApiConfig) -> Self {
        Self {
            listen: config.listen.to_string(),
            tls: Some(apiproxy::TlsIdentity {
                client_ca: config.client_ca.pem().to_owned(),
                certificate: config.certificate.pem().to_owned(),
                private_key: config.private_key.expose_pem().to_owned(),
            }),
        }
    }
}

impl TryFrom<apiproxy::Configuration> for ApiConfig {
    type Error = InvalidMessage;

    fn try_from(message: apiproxy::Configuration) -> Result<Self, Self::Error> {
        let listen = message.listen.parse::<SocketAddr>().field("listen")?;
        let tls = invalid_message::required(message.tls, "tls")?;
        Ok(Self {
            listen,
            client_ca: Certificates::from_pem(tls.client_ca).field("tls.client_ca")?,
            certificate: Certificates::from_pem(tls.certificate).field("tls.certificate")?,
            private_key: PrivateKey::from_pem(tls.private_key).field("tls.private_key")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use controllers_helpers::testing;

    use super::*;

    fn config() -> ApiConfig {
        let (certificate, private_key) = testing::certificate_and_key();
        ApiConfig {
            listen: "[2001:db8::1]:7443".parse().unwrap(),
            client_ca: Certificates::from_pem(certificate.clone()).unwrap(),
            certificate: Certificates::from_pem(certificate).unwrap(),
            private_key: PrivateKey::from_pem(private_key).unwrap(),
        }
    }

    #[test]
    fn round_trips_with_the_private_key() {
        let config = config();
        let message = apiproxy::Configuration::from(config.clone());
        assert_eq!(message.listen, "[2001:db8::1]:7443");
        assert!(
            message
                .tls
                .as_ref()
                .unwrap()
                .private_key
                .contains("PRIVATE KEY")
        );
        assert_eq!(ApiConfig::try_from(message).unwrap(), config);
    }

    #[test]
    fn rejects_invalid_configurations() {
        let valid = apiproxy::Configuration::from(config());
        let mut no_key = valid.clone();
        no_key.tls.as_mut().unwrap().private_key.clear();
        let mut key_as_ca = valid.clone();
        let tls = key_as_ca.tls.as_mut().unwrap();
        tls.client_ca = tls.private_key.clone();
        for (message, field) in [
            (
                apiproxy::Configuration {
                    listen: "0.0.0.0".to_owned(),
                    ..valid.clone()
                },
                "listen",
            ),
            (
                apiproxy::Configuration {
                    tls: None,
                    ..valid.clone()
                },
                "tls",
            ),
            (no_key, "tls.private_key"),
            (key_as_ca, "tls.client_ca"),
        ] {
            let error = ApiConfig::try_from(message).unwrap_err();
            assert_eq!(error.field(), field);
            assert!(!error.to_string().contains("PRIVATE KEY"), "{error}");
        }
    }
}

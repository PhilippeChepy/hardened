//! The settings as `hardened.machine.v1.Settings`, the answer of `Machine.GetSettings`.

use kubelet_controller::kubelet;
use machine_apiproxy::apiproxy;
use time_controller::time;

use crate::machine;
use crate::machine::registry_credential;
use crate::{Auth, ModuleLoad, Registry, Settings};

impl Settings {
    /// The settings as the API shows them: the secrets (bootstrap token, the API's private key,
    /// registry passwords and tokens) left empty, everything else as is.
    #[must_use]
    pub fn to_proto_without_secrets(&self) -> machine::Settings {
        let settings = self.clone();
        let registries = settings.container_registry;
        let registry_mirrors = registries
            .written_mirrors()
            .map(|(registry, endpoints)| machine::RegistryMirror {
                registry,
                endpoints,
            })
            .collect();
        machine::Settings {
            sysctl: settings
                .kernel
                .sysctl
                .into_iter()
                .map(|(key, value)| (key.into(), value))
                .collect(),
            kernel_modules: settings
                .kernel
                .modules
                .into_iter()
                .map(|(name, load)| machine::KernelModule {
                    name: name.into(),
                    load: module_load(load).into(),
                })
                .collect(),
            hostname: settings.network.hostname.map(String::from),
            dns: Some(settings.dns.into()),
            time_servers: settings
                .ntp
                .time_servers
                .into_iter()
                .map(String::from)
                .collect(),
            kubernetes: settings.kubernetes.map(|config| kubelet::Kubelet {
                bootstrap_token: String::new(),
                ..config.into()
            }),
            containers: Some(settings.hardened.containers.into()),
            registry_mirrors,
            registry_credentials: registries
                .credentials
                .into_iter()
                .map(|(registry, auth)| credential_without_secret(registry, auth))
                .collect(),
            api: settings.hardened.api.map(|config| {
                let mut api = apiproxy::Configuration::from(config);
                if let Some(tls) = &mut api.tls {
                    tls.private_key.clear();
                }
                api
            }),
            storage: Some(settings.hardened.storage.into()),
            time_source: time::Source::from(settings.hardened.time.source).into(),
        }
    }
}

#[must_use]
fn module_load(load: ModuleLoad) -> machine::ModuleLoad {
    match load {
        ModuleLoad::Never => machine::ModuleLoad::Never,
        ModuleLoad::AsDependency => machine::ModuleLoad::AsDependency,
        ModuleLoad::AtBoot => machine::ModuleLoad::AtBoot,
    }
}

/// The credential of `registry`, its password or token left empty, its username kept.
#[must_use]
fn credential_without_secret(registry: Registry, auth: Auth) -> machine::RegistryCredential {
    let auth = match auth {
        Auth::Basic { username, .. } => {
            registry_credential::Auth::Basic(registry_credential::Basic {
                username: username.into(),
                password: String::new(),
            })
        }
        Auth::Encoded(_) => registry_credential::Auth::Encoded(String::new()),
        Auth::IdentityToken(_) => registry_credential::Auth::IdentityToken(String::new()),
    };
    machine::RegistryCredential {
        registry: registry.into(),
        auth: Some(auth),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use controllers_helpers::base64_text;
    use controllers_helpers::testing;
    use kubelet_controller::testing::full_toml;

    use super::*;

    pub(crate) fn full_settings() -> Settings {
        let (certificate, key) = testing::certificate_and_key();
        let certificate = base64_text::encode(certificate);
        let key = base64_text::encode(key);
        let kubernetes = full_toml().replace("\n[", "\n[kubernetes.");
        let document = format!(
            r#"
[kernel.sysctl]
"net.ipv4.ip_forward" = "1"

[kernel.modules.wireguard]
autoload = true

[network]
hostname = "web-1"

[dns]
name-servers = ["192.0.2.53"]

[ntp]
time-servers = ["time.example.com"]

[[container-registry.mirrors]]
registry = "*"
endpoint = ["https://global.example.com"]

[[container-registry.mirrors]]
registry = "http://registry.local:5000"
endpoint = ["https://mirror.example.com"]

[[container-registry.credentials]]
registry = "docker.io"
username = "me"
password = "hunter2"

[[container-registry.credentials]]
registry = "ghcr.io"
identitytoken = "token-1"

[[container-registry.credentials]]
registry = "quay.io"
auth = "bWU6aHVudGVyMg=="

[hardened.api]
client-ca = "{certificate}"
certificate = "{certificate}"
private-key = "{key}"

[hardened.storage]
encryption = "tpm"

[hardened.containers.web]
image = "nginx:1.29"

[kubernetes]
{kubernetes}"#
        );
        toml::from_str(&document).unwrap()
    }

    #[test]
    fn get_settings_leaves_the_secrets_empty() {
        let settings = full_settings();
        let message = settings.to_proto_without_secrets();

        let kubelet = message.kubernetes.as_ref().unwrap();
        assert_eq!(kubelet.bootstrap_token, "");
        assert_eq!(kubelet.api_server, "https://k8s.example.com:6443");
        let api = message.api.as_ref().unwrap();
        assert_eq!(api.tls.as_ref().unwrap().private_key, "");
        assert!(
            api.tls
                .as_ref()
                .unwrap()
                .certificate
                .contains("CERTIFICATE")
        );
        let auths: Vec<_> = message
            .registry_credentials
            .iter()
            .map(|credential| credential.auth.clone().unwrap())
            .collect();
        assert_eq!(
            auths,
            [
                registry_credential::Auth::Basic(registry_credential::Basic {
                    username: "me".to_owned(),
                    password: String::new(),
                }),
                registry_credential::Auth::IdentityToken(String::new()),
                registry_credential::Auth::Encoded(String::new()),
            ]
        );
        let shown = format!("{message:?}");
        for secret in [
            "hunter2",
            "token-1",
            "bWU6aHVudGVyMg==",
            "abcdef.",
            "PRIVATE KEY",
        ] {
            assert!(!shown.contains(secret), "{secret} shown");
        }

        assert_eq!(message.sysctl["net.ipv4.ip_forward"], "1");
        assert_eq!(message.kernel_modules[0].name, "wireguard");
        assert_eq!(message.hostname.as_deref(), Some("web-1"));
        assert_eq!(message.dns.as_ref().unwrap().name_servers, ["192.0.2.53"]);
        assert_eq!(message.time_servers, ["time.example.com"]);
        let mirrors: Vec<_> = message
            .registry_mirrors
            .iter()
            .map(|mirror| mirror.registry.as_str())
            .collect();
        assert_eq!(mirrors, ["*", "http://registry.local:5000"]);
        assert_eq!(
            message.storage.unwrap().encryption,
            i32::from(storage_controller::storage::Encryption::Tpm)
        );
    }

    #[test]
    fn declares_the_containers() {
        let settings: Settings =
            toml::from_str("[hardened.containers.web]\nimage = \"nginx:1.29\"\n").unwrap();
        let message = settings.to_proto_without_secrets();
        let containers = message.containers.as_ref().unwrap();
        assert_eq!(containers.workloads[0].name, "web");
        assert_eq!(
            containers.workloads[0].spec.as_ref().unwrap().image,
            "docker.io/library/nginx:1.29"
        );
    }

    #[test]
    fn absent_parts_are_absent() {
        let message = Settings::default().to_proto_without_secrets();
        assert_eq!(message.kubernetes, None);
        assert_eq!(message.containers.unwrap().workloads, []);
        assert_eq!(message.api, None);
        assert_eq!(message.hostname, None);
    }
}

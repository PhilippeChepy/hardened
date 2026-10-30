//! The user-data document.

use std::io;

use serde::Deserialize;

use crate::Settings;
use crate::settings::encoding;

/// A reason why user-data was rejected.
#[must_use]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Its gzip compression is broken.
    #[error("invalid user-data encoding: gzip: {0}")]
    Gzip(io::Error),
    /// Decompressed, it is too large (a gzip bomb).
    #[error(
        "invalid user-data encoding: decompressed user-data exceeds {} bytes",
        encoding::MAX_DECODED
    )]
    TooLarge,
    /// It is not UTF-8 text.
    #[error("invalid user-data encoding: user-data is not valid UTF-8")]
    NotUtf8,
    /// It is not valid TOML, or a setting is invalid.
    #[error("invalid user-data: {0}")]
    Toml(toml::de::Error),
}

/// Root of the user-data document.
#[derive(Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct UserData {
    /// `[settings]`.
    #[serde(default)]
    pub settings: Settings,
}

impl UserData {
    /// Parses user-data as fetched from the platform.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        toml::from_str(&encoding::decode(raw)?).map_err(Error::Toml)
    }
}

#[cfg(test)]
mod tests {
    use controllers_helpers::base64_text;
    use controllers_helpers::testing;
    use storage_controller::Encryption;
    use workload_controller::RestartPolicy;

    use super::*;
    use crate::ModuleLoad;

    /// A certificate and its key, base64-encoded as in user-data.
    fn pki() -> (String, String) {
        let (certificate, key) = testing::certificate_and_key();
        (base64_text::encode(certificate), base64_text::encode(key))
    }

    fn full_document() -> String {
        let (cert, key) = pki();
        format!(
            r#"
[settings.network]
hostname = "web-1"

[settings.kernel.sysctl]
"net.ipv4.ip_forward" = "1"

[settings.dns]
name-servers = ["192.0.2.53", "2001:db8::53"]
search-list = ["corp.example.com"]

[settings.ntp]
time-servers = ["time.example.com", "192.0.2.123", "2001:db8::123"]

[settings.kernel.modules.wireguard]
autoload = true

[settings.kernel.modules.dccp]
allowed = false

[settings.hardened.api]
client-ca = "{cert}"
certificate = "{cert}"
private-key = "{key}"

[settings.hardened.storage]
encryption = "tpm"

[settings.hardened.containers.web]
image = "nginx:1.29"
env = {{ FOO = "bar" }}
restart = "on-failure"
mounts = [{{ source = "/var/lib/web", destination = "/data" }}]
"#
        )
    }

    #[test]
    fn parses_full_document() {
        let settings = UserData::parse(full_document().as_bytes())
            .unwrap()
            .settings;
        assert_eq!(settings.network.hostname.unwrap().as_str(), "web-1");
        let modules = &settings.kernel.modules;
        assert_eq!(modules["wireguard"], ModuleLoad::AtBoot);
        assert_eq!(modules["dccp"], ModuleLoad::Never);
        assert_eq!(settings.dns.name_servers.len(), 2);
        assert_eq!(settings.dns.search_list[0].as_str(), "corp.example.com");
        assert_eq!(settings.ntp.time_servers.len(), 3);
        let api = settings.hardened.api.as_ref().unwrap();
        assert_eq!(api.listen.port(), 7443, "the default port");
        assert_eq!(settings.hardened.storage.encryption, Encryption::Tpm);
        let web = &settings.hardened.containers["web"];
        assert!(web.enabled, "enabled by default");
        assert_eq!(web.workload.image.as_str(), "docker.io/library/nginx:1.29");
        assert_eq!(web.workload.restart, RestartPolicy::OnFailure);
    }

    #[test]
    fn empty_user_data_is_valid() {
        assert_eq!(UserData::parse(b"").unwrap(), UserData::default());
    }

    #[test]
    fn rejects_invalid_documents() {
        for (document, why) in [
            ("[settings.hots]\nhostname = \"x\"\n", "unknown table"),
            ("[settings.network]\nhostname = \"-x\"\n", "bad hostname"),
            ("[settings.hardened.api]\n", "API without TLS material"),
            (
                "[settings.hardened.api]\nclient-ca = \"x\"\ncertificate = \"x\"\n\
                 private-key = \"x\"\n",
                "bad PEM",
            ),
            (
                "[settings.hardened.containers.Web]\nimage = \"i\"\n",
                "bad workload name",
            ),
            (
                "[settings.hardened.containers.x]\nimage = \"\"\n",
                "empty image",
            ),
            (
                "[settings.hardened.containers.x]\nimage = \"i\"\n\
                 restart = \"sometimes\"\n",
                "bad restart policy",
            ),
            (
                "[settings.hardened.containers.x]\nimage = \"i\"\n\
                 env = { \"A=B\" = \"c\" }\n",
                "bad env name",
            ),
            (
                "[settings.hardened.containers.x]\nimage = \"i\"\n\
                 command = [\"a\\u0000b\"]\n",
                "NUL in the command",
            ),
            (
                "[settings.hardened.containers.x]\nimage = \"i\"\n\
                 mounts = [{ source = \"/var/a,b\", destination = \"/data\" }]\n",
                "comma in a mount path",
            ),
            (
                "[settings.kernel.sysctl]\n\"../x\" = \"1\"\n",
                "bad sysctl key",
            ),
            (
                "[settings.kernel.modules.\"a/b\"]\nautoload = true\n",
                "bad module name",
            ),
            (
                "[settings.dns]\nname-servers = [\"dns.example\"]\n",
                "name server that is not an IP",
            ),
            (
                "[settings.dns]\nsearch-list = [\"a b\"]\n",
                "bad search domain",
            ),
            (
                "[settings.ntp]\ntime-servers = [\"ntp://time.example\"]\n",
                "time server that is a URL",
            ),
            ("[settings.ntp]\noptions = [\"iburst\"]\n", "chrony options"),
            (
                "[settings.hardened.storage]\nencryption = \"luks\"\n",
                "unknown encryption",
            ),
            (
                "[settings.hardened.storage]\nencryption = true\n",
                "encryption as a boolean",
            ),
            (
                "[settings.hardened.storage]\nencrypted = \"tpm\"\n",
                "unknown storage key",
            ),
        ] {
            assert!(
                UserData::parse(document.as_bytes()).is_err(),
                "{why} accepted"
            );
        }
    }

    /// `[settings.kubernetes]`, with `extra` keys.
    fn kubernetes(extra: &str) -> String {
        let (cert, _) = pki();
        format!(
            "[settings.kubernetes]\n\
             api-server = \"https://k8s.example.com:6443\"\n\
             cluster-certificate = \"{cert}\"\nbootstrap-token = \"abcdef.0123456789abcdef\"\n\
             {extra}\n"
        )
    }

    #[test]
    fn kubernetes_settings() {
        let settings = UserData::parse(kubernetes("").as_bytes()).unwrap().settings;
        let config = settings.kubernetes.as_ref().unwrap();
        assert_eq!(config.bootstrap_token.expose(), "abcdef.0123456789abcdef");
        assert_eq!(config.api_server.as_str(), "https://k8s.example.com:6443");
        let text = toml::to_string(&settings).unwrap();
        assert_eq!(
            toml::from_str::<Settings>(&text).unwrap(),
            settings,
            "serialized with the bootstrap token"
        );
    }

    #[test]
    fn rejects_invalid_kubernetes_settings() {
        let mut documents: Vec<(String, &str)> = [
            (
                "node-labels = { \"node-role.kubernetes.io/worker\" = \"\" }",
                "label kubelet may not set",
            ),
            ("node-labels = { \"a b\" = \"x\" }", "bad label key"),
            ("node-labels = { app = \"a,b\" }", "bad label value"),
            (
                "node-taints = { dedicated = [\"gpu:Sometimes\"] }",
                "bad taint effect",
            ),
            ("max-pods = 0", "no pods"),
            ("cloud-provider = \"aws\"", "unknown cloud provider"),
            ("node-ip = \"192.0.2.1\"", "node-ip, which does not exist"),
            (
                "cluster-dns-ip = [\"kube-dns\"]",
                "cluster DNS that is not an IP",
            ),
            ("client-key = \"x\"", "client certificate credentials"),
            ("kubelet-version = \"1.37\"", "unknown key"),
            (
                "kube-reserved = { gpu = \"1\" }",
                "unknown reserved resource",
            ),
            ("kube-reserved = { cpu = \"-1\" }", "negative reservation"),
            ("system-reserved = { memory = \"1GB\" }", "bad quantity"),
            (
                "eviction-hard = { \"memory.free\" = \"1%\" }",
                "unknown eviction signal",
            ),
            (
                "eviction-hard = { \"memory.available\" = \"100%\" }",
                "100% threshold",
            ),
            (
                "eviction-soft = { \"memory.available\" = \"10%\" }",
                "soft threshold without grace period",
            ),
            (
                "eviction-soft-grace-period = { \"memory.available\" = \"1m\" }",
                "grace period without soft threshold",
            ),
            (
                "eviction-max-pod-grace-period = -1",
                "negative max pod grace period",
            ),
            (
                "image-gc-high-threshold-percent = 101",
                "percentage above 100",
            ),
            (
                "image-gc-high-threshold-percent = 60\nimage-gc-low-threshold-percent = \"60\"",
                "equal thresholds",
            ),
            (
                "image-minimum-gc-age = \"2m\"\nimage-maximum-gc-age = \"1m\"",
                "maximum age below the minimum",
            ),
            ("image-minimum-gc-age = \"5 minutes\"", "bad duration"),
            (
                "[settings.kubernetes.static-pods.web]\nenabled = true",
                "static pod without manifest",
            ),
        ]
        .into_iter()
        .map(|(extra, why)| (kubernetes(extra), why))
        .collect();
        let without = |key: &str| {
            kubernetes("")
                .lines()
                .filter(|line| !line.starts_with(key))
                .collect::<Vec<_>>()
                .join("\n")
        };
        documents.extend([
            (without("bootstrap-token"), "no bootstrap token"),
            (without("api-server"), "no API server"),
            (without("cluster-certificate"), "no cluster CA"),
            (
                kubernetes("").replace("abcdef.0123456789abcdef", "abcdef"),
                "bad token",
            ),
            (
                kubernetes("").replace("https://k8s.example.com:6443", "http://k8s"),
                "plain HTTP API server",
            ),
            (
                kubernetes(&format!(
                    "[settings.kubernetes.static-pods.Web]\nmanifest = \"{}\"",
                    base64_text::encode("apiVersion: v1\nkind: Pod\nmetadata: {}\n")
                )),
                "bad static pod name",
            ),
            (
                kubernetes(&format!(
                    "[settings.kubernetes.static-pods.web]\nmanifest = \"{}\"",
                    base64_text::encode("apiVersion: apps/v1\nkind: Deployment\nmetadata: {}\n")
                )),
                "static pod that is not a Pod",
            ),
        ]);
        for (document, why) in documents {
            assert!(
                UserData::parse(document.as_bytes()).is_err(),
                "{why} accepted"
            );
        }
    }

    #[test]
    fn container_registry_settings() {
        let document = r#"
[[settings.container-registry.mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com"]

[[settings.container-registry.credentials]]
registry = "docker.io"
username = "me"
password = "hunter2"
"#;
        let settings = UserData::parse(document.as_bytes()).unwrap().settings;
        assert_eq!(settings.container_registry.mirrors.len(), 1);
        assert_eq!(settings.container_registry.credentials.len(), 1);
        let text = toml::to_string(&settings).unwrap();
        assert_eq!(toml::from_str::<Settings>(&text).unwrap(), settings);
    }
}

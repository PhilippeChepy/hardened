//! The user-data settings model.
//!
//! User-data is TOML in the Bottlerocket style (`[settings.<group>]`, kebab-case keys), optionally
//! gzip-compressed and/or base64-encoded (see [`decode`]). Unknown keys are rejected so typos fail
//! loudly at boot instead of being silently ignored.
//!
//! Parsing is validation: every field has a type that only admits valid values (see
//! [`crate::types`]), so a `Settings` value is valid by construction.

mod decode;

use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

pub use decode::decode;

use crate::types::{
    Certificates, ContainerPath, DomainName, Hostname, ImageRef, InvalidValue, ModuleName, PrivateKey, SysctlKey,
    VarPath, WorkloadName,
};

/// Root of the user-data document.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct UserData {
    #[serde(default)]
    pub settings: Settings,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub kernel: KernelSettings,
    #[serde(default)]
    pub network: NetworkSettings,
    #[serde(default)]
    pub dns: DnsSettings,
    #[serde(default)]
    pub api: ApiSettings,
    /// Workloads, keyed by name.
    #[serde(default)]
    pub containers: BTreeMap<WorkloadName, ContainerSettings>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KernelSettings {
    /// Extra sysctls, applied after (and able to override) the hardened defaults.
    #[serde(default)]
    pub sysctl: BTreeMap<SysctlKey, String>,
    /// Kernel modules shipped in the image, keyed by module name.
    #[serde(default)]
    pub modules: BTreeMap<ModuleName, ModuleSettings>,
}

/// The kernel never loads modules by itself (no modprobe helper), so these only steer dust-init.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawModuleSettings", into = "RawModuleSettings")]
pub struct ModuleSettings {
    /// When false, dust-init never loads the module, not even as a dependency.
    pub allowed: bool,
    /// Load the module (and its dependencies) at boot.
    pub autoload: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawModuleSettings {
    #[serde(default = "enabled_by_default")]
    allowed: bool,
    #[serde(default)]
    autoload: bool,
}

impl TryFrom<RawModuleSettings> for ModuleSettings {
    type Error = &'static str;

    fn try_from(raw: RawModuleSettings) -> Result<Self, Self::Error> {
        if raw.autoload && !raw.allowed {
            return Err("a module cannot be autoloaded when it is not allowed");
        }
        Ok(Self {
            allowed: raw.allowed,
            autoload: raw.autoload,
        })
    }
}

impl From<ModuleSettings> for RawModuleSettings {
    fn from(settings: ModuleSettings) -> Self {
        Self {
            allowed: settings.allowed,
            autoload: settings.autoload,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct NetworkSettings {
    /// Overrides the hostname provided by the platform metadata (Bottlerocket's key).
    pub hostname: Option<Hostname>,
}

/// The resolver configuration (Bottlerocket's `settings.dns`). Each list, when set, replaces
/// what DHCP provides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsSettings {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<IpAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_list: Vec<DomainName>,
}

/// The remote API, served by `dust-api`.
///
/// Enabling it requires the complete TLS identity, so an enabled API without certificates
/// cannot be represented.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawApiSettings", into = "RawApiSettings")]
pub enum ApiSettings {
    #[default]
    Disabled,
    Enabled(ApiConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    pub listen: SocketAddr,
    pub tls: TlsIdentity,
}

/// Server identity of the API, and the CA its clients must chain to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentity {
    pub client_ca: Certificates,
    pub certificate: Certificates,
    pub private_key: PrivateKey,
}

impl ApiConfig {
    pub const DEFAULT_PORT: u16 = 7443;

    fn default_listen() -> SocketAddr {
        SocketAddr::from(([0, 0, 0, 0], Self::DEFAULT_PORT))
    }
}

/// `[settings.api]` as written in user-data.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawApiSettings {
    #[serde(default)]
    enabled: bool,
    #[serde(default = "ApiConfig::default_listen")]
    listen: SocketAddr,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ca: Option<Certificates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    certificate: Option<Certificates>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<PrivateKey>,
}

impl TryFrom<RawApiSettings> for ApiSettings {
    type Error = String;

    fn try_from(raw: RawApiSettings) -> Result<Self, Self::Error> {
        if !raw.enabled {
            return Ok(Self::Disabled);
        }
        match (raw.client_ca, raw.certificate, raw.private_key) {
            (Some(client_ca), Some(certificate), Some(private_key)) => Ok(Self::Enabled(ApiConfig {
                listen: raw.listen,
                tls: TlsIdentity {
                    client_ca,
                    certificate,
                    private_key,
                },
            })),
            _ => Err("client-ca, certificate and private-key are required when the API is enabled".into()),
        }
    }
}

impl From<ApiSettings> for RawApiSettings {
    fn from(api: ApiSettings) -> Self {
        match api {
            ApiSettings::Disabled => Self {
                enabled: false,
                listen: ApiConfig::default_listen(),
                client_ca: None,
                certificate: None,
                private_key: None,
            },
            ApiSettings::Enabled(config) => Self {
                enabled: true,
                listen: config.listen,
                client_ca: Some(config.tls.client_ca),
                certificate: Some(config.tls.certificate),
                private_key: Some(config.tls.private_key),
            },
        }
    }
}

/// `[settings.containers.<name>]`: a workload declared in user-data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawContainerSettings", into = "RawContainerSettings")]
pub struct ContainerSettings {
    pub enabled: bool,
    pub workload: ImageWorkload,
}

/// What to run for an image-based workload, wherever it was declared (user-data or the API).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ImageWorkload {
    pub image: ImageRef,
    /// Overrides the image entrypoint.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub command: Vec<String>,
    /// Overrides the image command.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub env: BTreeMap<EnvName, String>,
    /// Runs with all capabilities and host devices, no seccomp filter and unmasked `/proc` and `/sys`.
    #[serde(default)]
    pub privileged: bool,
    #[serde(default)]
    pub restart: RestartPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mounts: Vec<MountSettings>,
    /// Also copies the workload's output to the serial console (debugging, smoke tests).
    #[serde(default)]
    pub console: bool,
}

/// The flat TOML table of a user-data container: `enabled` next to the workload fields.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawContainerSettings {
    #[serde(default = "enabled_by_default")]
    enabled: bool,
    image: ImageRef,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    command: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    args: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    env: BTreeMap<EnvName, String>,
    #[serde(default)]
    privileged: bool,
    #[serde(default)]
    restart: RestartPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    mounts: Vec<MountSettings>,
    #[serde(default)]
    console: bool,
}

fn enabled_by_default() -> bool {
    true
}

impl TryFrom<RawContainerSettings> for ContainerSettings {
    type Error = InvalidValue;

    fn try_from(raw: RawContainerSettings) -> Result<Self, Self::Error> {
        let workload = ImageWorkload {
            image: raw.image,
            command: raw.command,
            args: raw.args,
            env: raw.env,
            privileged: raw.privileged,
            restart: raw.restart,
            mounts: raw.mounts,
            console: raw.console,
        };
        workload.check_arguments()?;
        Ok(Self {
            enabled: raw.enabled,
            workload,
        })
    }
}

impl From<ContainerSettings> for RawContainerSettings {
    fn from(settings: ContainerSettings) -> Self {
        let w = settings.workload;
        Self {
            enabled: settings.enabled,
            image: w.image,
            command: w.command,
            args: w.args,
            env: w.env,
            privileged: w.privileged,
            restart: w.restart,
            mounts: w.mounts,
            console: w.console,
        }
    }
}

impl ImageWorkload {
    /// Arguments and environment values end up in `execve`, which cannot carry NUL bytes.
    pub fn check_arguments(&self) -> Result<(), InvalidValue> {
        let strings = self.command.iter().chain(&self.args).chain(self.env.values());
        match strings.into_iter().find(|s| s.contains('\0')) {
            Some(s) => Err(InvalidValue::nul_byte(s)),
            None => Ok(()),
        }
    }
}

crate::types::validated_string!(
    /// Environment variable name: non-empty, without `=` or NUL.
    EnvName,
    "environment variable name",
    |name| {
        if name.is_empty() || name.contains(['=', '\0']) {
            Err("must be non-empty, without '=' or NUL")
        } else {
            Ok(())
        }
    }
);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RestartPolicy {
    #[default]
    Always,
    OnFailure,
    Never,
}

impl RestartPolicy {
    /// Whether a workload that exited with `exit_code` is started again.
    pub fn restarts_after(self, exit_code: i32) -> bool {
        match self {
            Self::Always => true,
            Self::OnFailure => exit_code != 0,
            Self::Never => false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct MountSettings {
    /// Host path; must live under `/var` (the only persistent, writable location).
    pub source: VarPath,
    pub destination: ContainerPath,
    #[serde(default)]
    pub read_only: bool,
}

/// A reason why user-data was rejected.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid user-data encoding: {0}")]
    Encoding(String),
    #[error("invalid user-data: {0}")]
    Toml(#[from] toml::de::Error),
}

impl UserData {
    /// Decodes and parses raw user-data as fetched from the platform.
    pub fn parse(raw: &[u8]) -> Result<Self, Error> {
        Ok(toml::from_str(&decode(raw)?)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A certificate and its key, base64-encoded as in user-data.
    fn pki() -> (String, String) {
        use base64::Engine;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["x".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let encode = |pem: String| base64::engine::general_purpose::STANDARD.encode(pem);
        (encode(cert.pem()), encode(key.serialize_pem()))
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

[settings.kernel.modules.wireguard]
autoload = true

[settings.kernel.modules.dccp]
allowed = false

[settings.api]
enabled = true
client-ca = "{cert}"
certificate = "{cert}"
private-key = "{key}"

[settings.containers.web]
image = "nginx:1.29"
env = {{ FOO = "bar" }}
restart = "on-failure"
mounts = [{{ source = "/var/lib/web", destination = "/data" }}]
"#
        )
    }

    #[test]
    fn parses_full_document() {
        let settings = UserData::parse(full_document().as_bytes()).unwrap().settings;
        assert_eq!(settings.network.hostname.unwrap().as_str(), "web-1");
        let modules = &settings.kernel.modules;
        assert!(modules["wireguard"].allowed && modules["wireguard"].autoload);
        assert!(!modules["dccp"].allowed && !modules["dccp"].autoload);
        assert_eq!(settings.dns.name_servers.len(), 2);
        assert_eq!(settings.dns.search_list[0].as_str(), "corp.example.com");
        let ApiSettings::Enabled(api) = &settings.api else {
            panic!("API should be enabled")
        };
        assert_eq!(api.listen.port(), ApiConfig::DEFAULT_PORT);
        let web = &settings.containers["web"];
        assert!(web.enabled);
        assert_eq!(web.workload.image.as_str(), "docker.io/library/nginx:1.29");
        assert_eq!(web.workload.restart, RestartPolicy::OnFailure);
    }

    #[test]
    fn serialization_redacts_the_private_key_and_round_trips() {
        let settings = UserData::parse(full_document().as_bytes()).unwrap().settings;
        let text = toml::to_string(&settings).unwrap();
        assert!(text.contains("private-key = \"<redacted>\""));
        assert!(!text.contains("PRIVATE KEY"));
        assert!(!text.contains("BEGIN"), "certificates serialize as base64");
        // The containers table round-trips (the API table cannot: its key is redacted).
        let back: BTreeMap<WorkloadName, ContainerSettings> =
            toml::from_str(&toml::to_string(&settings.containers).unwrap()).unwrap();
        assert_eq!(back, settings.containers);
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
            ("[settings.api]\nenabled = true\n", "API without TLS material"),
            (
                "[settings.api]\nenabled = true\nclient-ca = \"x\"\ncertificate = \"x\"\nprivate-key = \"x\"\n",
                "bad PEM",
            ),
            ("[settings.containers.Web]\nimage = \"i\"\n", "bad workload name"),
            ("[settings.containers.x]\nimage = \"\"\n", "empty image"),
            (
                "[settings.containers.x]\nimage = \"i\"\nrestart = \"sometimes\"\n",
                "bad restart policy",
            ),
            (
                "[settings.containers.x]\nimage = \"i\"\nenv = { \"A=B\" = \"c\" }\n",
                "bad env name",
            ),
            (
                "[settings.containers.x]\nimage = \"i\"\nargs = [\"a\\u0000b\"]\n",
                "NUL in args",
            ),
            ("[settings.kernel.sysctl]\n\"../x\" = \"1\"\n", "bad sysctl key"),
            (
                "[settings.kernel.modules.\"a/b\"]\nautoload = true\n",
                "bad module name",
            ),
            (
                "[settings.kernel.modules.x]\nallowed = false\nautoload = true\n",
                "autoload of a module that is not allowed",
            ),
            ("[settings.kernel.modules.x]\nload = true\n", "former module key"),
            ("[settings.network]\nnameservers = [\"1.1.1.1\"]\n", "former DNS key"),
            (
                "[settings.dns]\nname-servers = [\"dns.example\"]\n",
                "name server that is not an IP",
            ),
            ("[settings.dns]\nsearch-list = [\"a b\"]\n", "bad search domain"),
        ] {
            assert!(UserData::parse(document.as_bytes()).is_err(), "{why} accepted");
        }
    }

    #[test]
    fn rejects_mounts_outside_var() {
        for source in ["/etc", "/var", "/var/../etc", "var/lib"] {
            let doc = format!(
                "[settings.containers.x]\nimage = \"i\"\nmounts = [{{ source = \"{source}\", destination = \"/d\" }}]\n"
            );
            assert!(UserData::parse(doc.as_bytes()).is_err(), "{source} accepted");
        }
    }

    #[test]
    fn restart_policies() {
        assert!(RestartPolicy::Always.restarts_after(0));
        assert!(!RestartPolicy::OnFailure.restarts_after(0));
        assert!(RestartPolicy::OnFailure.restarts_after(137));
        assert!(!RestartPolicy::Never.restarts_after(1));
    }
}

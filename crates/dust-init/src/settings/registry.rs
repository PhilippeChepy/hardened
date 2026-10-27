//! `[settings.container-registry]`: registry mirrors and credentials, for every image pull of the
//! machine (kubelet's pods and dust-init's workloads). Bottlerocket's keys and value formats
//! (`bottlerocket-settings-models`, `settings-extensions/container-registry`), rendered as
//! Bottlerocket's `thar-be-registries` does.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::types::{InvalidValue, PrivateKey, validated_string};

/// containerd's name for Docker Hub's registry, which `docker.io` references resolve to.
const DOCKER_HUB: &str = "docker.io";
const DOCKER_HUB_REGISTRY: &str = "registry-1.docker.io";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRegistrySettings", into = "RawRegistrySettings")]
pub struct RegistrySettings {
    pub mirrors: Vec<Mirror>,
    pub credentials: Vec<Credential>,
}

/// Endpoints tried, in order, before the registry itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Mirror {
    pub registry: Registry,
    pub endpoint: Vec<Endpoint>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawCredential", into = "RawCredential")]
pub struct Credential {
    pub registry: Registry,
    pub auth: Auth,
}

/// What containerd sends a registry (its CRI plugin's `AuthConfig`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    UsernamePassword {
        username: SingleLine,
        password: Secret,
    },
    /// The base64 of `<username>:<password>`.
    Basic(Secret),
    IdentityToken(Secret),
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawRegistrySettings {
    #[serde(default, skip_serializing_if = "Mirrors::is_empty")]
    mirrors: Mirrors,
    #[serde(default, alias = "creds", skip_serializing_if = "Vec::is_empty")]
    credentials: Vec<Credential>,
}

/// Bottlerocket also takes mirrors as a table of registry → endpoints, its former form.
#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum Mirrors {
    List(Vec<Mirror>),
    Table(std::collections::BTreeMap<Registry, Vec<Endpoint>>),
}

impl Default for Mirrors {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

impl Mirrors {
    fn is_empty(&self) -> bool {
        match self {
            Self::List(list) => list.is_empty(),
            Self::Table(table) => table.is_empty(),
        }
    }
}

impl TryFrom<RawRegistrySettings> for RegistrySettings {
    type Error = String;

    fn try_from(raw: RawRegistrySettings) -> Result<Self, Self::Error> {
        let mirrors = match raw.mirrors {
            Mirrors::List(list) => list,
            Mirrors::Table(table) => table
                .into_iter()
                .map(|(registry, endpoint)| Mirror { registry, endpoint })
                .collect(),
        };
        let mut seen = BTreeSet::new();
        for mirror in &mirrors {
            if mirror.endpoint.is_empty() {
                return Err(format!("mirrors of {}: no endpoint", mirror.registry));
            }
            if !seen.insert(mirror.registry.directory()) {
                return Err(format!("mirrors of {}: given twice", mirror.registry));
            }
        }
        let mut seen = BTreeSet::new();
        for credential in &raw.credentials {
            if !seen.insert(credential.registry.credentials_host()) {
                return Err(format!("credentials of {}: given twice", credential.registry));
            }
        }
        Ok(Self {
            mirrors,
            credentials: raw.credentials,
        })
    }
}

impl From<RegistrySettings> for RawRegistrySettings {
    fn from(settings: RegistrySettings) -> Self {
        Self {
            mirrors: Mirrors::List(settings.mirrors),
            credentials: settings.credentials,
        }
    }
}

/// `[[settings.container-registry.credentials]]` as written in user-data.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
struct RawCredential {
    registry: Registry,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<SingleLine>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identitytoken: Option<Secret>,
}

impl TryFrom<RawCredential> for Credential {
    type Error = String;

    fn try_from(raw: RawCredential) -> Result<Self, Self::Error> {
        if raw.registry.is_default() {
            return Err("credentials are for one registry, not \"*\"".into());
        }
        let auth = match (raw.username, raw.password, raw.auth, raw.identitytoken) {
            (Some(username), Some(password), None, None) => Auth::UsernamePassword { username, password },
            (None, None, Some(auth), None) => {
                let decoded = crate::types::decode_base64(auth.expose().as_bytes())
                    .and_then(|bytes| String::from_utf8(bytes).ok());
                if !decoded.is_some_and(|text| text.contains(':')) {
                    return Err(format!(
                        "credentials of {}: auth must be the base64 of <username>:<password>",
                        raw.registry
                    ));
                }
                Auth::Basic(auth)
            }
            (None, None, None, Some(token)) => Auth::IdentityToken(token),
            _ => {
                return Err(format!(
                    "credentials of {}: give username and password, auth, or identitytoken",
                    raw.registry
                ));
            }
        };
        Ok(Self {
            registry: raw.registry,
            auth,
        })
    }
}

impl From<Credential> for RawCredential {
    fn from(credential: Credential) -> Self {
        let mut raw = Self {
            registry: credential.registry,
            username: None,
            password: None,
            auth: None,
            identitytoken: None,
        };
        match credential.auth {
            Auth::UsernamePassword { username, password } => {
                raw.username = Some(username);
                raw.password = Some(password);
            }
            Auth::Basic(auth) => raw.auth = Some(auth),
            Auth::IdentityToken(token) => raw.identitytoken = Some(token),
        }
        raw
    }
}

validated_string!(
    /// A registry: `*` (every registry, for mirrors), or `[http://|https://]<host>[:<port>]`.
    Registry,
    "registry",
    |registry| {
        if registry == "*" {
            return Ok(());
        }
        let host = registry
            .strip_prefix("https://")
            .or_else(|| registry.strip_prefix("http://"))
            .unwrap_or(registry);
        let authority: http::uri::Authority = host.parse().map_err(|_| "must be a host, with an optional port")?;
        if authority.as_str().contains('@') || host.is_empty() {
            Err("must be a host, with an optional port")
        } else {
            Ok(())
        }
    }
);

impl Registry {
    fn is_default(&self) -> bool {
        self.as_str() == "*"
    }

    /// The host and port, and the scheme to reach it: the one given, else HTTP on port 80 and
    /// HTTPS otherwise (as `thar-be-registries` infers it).
    fn host_and_scheme(&self) -> (&str, &'static str) {
        let registry = self.as_str();
        if let Some(host) = registry.strip_prefix("http://") {
            return (host, "http");
        }
        let host = registry.strip_prefix("https://").unwrap_or(registry);
        (host, if host.ends_with(":80") { "http" } else { "https" })
    }

    /// Its directory under containerd's `config_path`: `_default` for `*`, `<host>_<port>_`
    /// with a port.
    pub fn directory(&self) -> String {
        if self.is_default() {
            return "_default".to_owned();
        }
        let (host, _) = self.host_and_scheme();
        match host.rsplit_once(':') {
            Some((name, port)) => format!("{name}_{port}_"),
            None => host.to_owned(),
        }
    }

    /// `server` of its `hosts.toml`: the registry itself, Docker Hub's for `docker.io`, none for
    /// `*`.
    pub fn server(&self) -> Option<String> {
        let (host, scheme) = self.host_and_scheme();
        match host {
            "*" => None,
            DOCKER_HUB => Some(format!("https://{DOCKER_HUB_REGISTRY}")),
            _ => Some(format!("{scheme}://{host}")),
        }
    }

    /// The host containerd looks credentials up with: the one it contacts, so Docker Hub's for
    /// `docker.io`.
    pub fn credentials_host(&self) -> String {
        match self.host_and_scheme().0 {
            DOCKER_HUB => DOCKER_HUB_REGISTRY.to_owned(),
            host => host.to_owned(),
        }
    }
}

validated_string!(
    /// A mirror endpoint: `[http://|https://]<host>[:<port>][/<path>]`.
    Endpoint,
    "registry mirror endpoint",
    |endpoint| {
        let uri: http::Uri = if endpoint.contains("://") {
            endpoint.parse()
        } else {
            format!("https://{endpoint}").parse()
        }
        .map_err(|_| "must be a URL")?;
        match (uri.scheme_str(), uri.authority()) {
            (Some("http" | "https"), Some(authority)) if !authority.as_str().contains('@') && uri.query().is_none() => {
                Ok(())
            }
            _ => Err("must be an http or https URL with a host, and no credentials or query"),
        }
    }
);

impl Endpoint {
    /// Whether it has a path, which replaces the registry's `/v2` path (`override_path`).
    pub fn has_path(&self) -> bool {
        let text = self.as_str();
        let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
        rest.split_once('/').is_some_and(|(_, path)| !path.is_empty())
    }
}

validated_string!(
    /// A non-empty value on a single line.
    SingleLine,
    "value",
    |text| {
        if text.is_empty() || text.contains(|c: char| c.is_control()) {
            Err("must be a non-empty single line")
        } else {
            Ok(())
        }
    }
);

/// A secret single-line value. Like [`PrivateKey`], never displayed, logged or serialized.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct Secret(String);

impl Secret {
    /// The value, to write containerd's configuration. The only way to read it.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Secret {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if text.is_empty() || text.contains(|c: char| c.is_control()) {
            return Err(InvalidValue::new(
                "secret",
                PrivateKey::REDACTED,
                "must be a non-empty single line",
            ));
        }
        Ok(Self(text))
    }
}

impl Serialize for Secret {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(PrivateKey::REDACTED)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PrivateKey::REDACTED)
    }
}

/// containerd's host configuration (`<config_path>/<directory>/hosts.toml`) of each mirrored
/// registry: its mirrors, for pulling and resolving, then the registry itself (or, for `*`, the
/// registry an image names).
///
/// Written by hand: containerd tries the hosts in the order of the file, which a `toml::Table`
/// (sorted) would not keep.
pub fn hosts_files(settings: &RegistrySettings) -> Vec<(String, String)> {
    // A TOML basic string, quoting and escaping as needed.
    let quoted = |text: &str| toml::Value::from(text).to_string();
    settings
        .mirrors
        .iter()
        .map(|mirror| {
            let mut file = String::from("# Generated by dust-init from settings.container-registry.\n");
            if let Some(server) = mirror.registry.server() {
                file.push_str(&format!("server = {}\n", quoted(&server)));
            }
            for endpoint in &mirror.endpoint {
                file.push_str(&format!(
                    "\n[host.{}]\ncapabilities = [\"pull\", \"resolve\"]\n",
                    quoted(endpoint.as_str())
                ));
                if endpoint.has_path() {
                    file.push_str("override_path = true\n");
                }
            }
            (mirror.registry.directory(), file)
        })
        .collect()
}

/// The `configs` table of containerd's CRI registry configuration: the credentials of each host,
/// which CRI pulls use when the request carries none (dust-init's workloads, and kubelet's pods
/// without image pull secrets).
pub fn cri_auth_configs(settings: &RegistrySettings) -> toml::Table {
    settings
        .credentials
        .iter()
        .map(|credential| {
            let mut auth = toml::Table::new();
            match &credential.auth {
                Auth::UsernamePassword { username, password } => {
                    auth.insert("username".into(), username.as_str().into());
                    auth.insert("password".into(), password.expose().into());
                }
                Auth::Basic(basic) => {
                    auth.insert("auth".into(), basic.expose().into());
                }
                Auth::IdentityToken(token) => {
                    auth.insert("identitytoken".into(), token.expose().into());
                }
            }
            let mut config = toml::Table::new();
            config.insert("auth".into(), auth.into());
            (credential.registry.credentials_host(), config.into())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<RegistrySettings, toml::de::Error> {
        toml::from_str(text)
    }

    #[test]
    fn registries() {
        for (registry, directory, server, credentials) in [
            (
                "docker.io",
                "docker.io",
                Some("https://registry-1.docker.io"),
                "registry-1.docker.io",
            ),
            ("*", "_default", None, "*"),
            (
                "registry.example.com:5000",
                "registry.example.com_5000_",
                Some("https://registry.example.com:5000"),
                "registry.example.com:5000",
            ),
            (
                "registry.example.com:80",
                "registry.example.com_80_",
                Some("http://registry.example.com:80"),
                "registry.example.com:80",
            ),
            (
                "http://registry.local:5000",
                "registry.local_5000_",
                Some("http://registry.local:5000"),
                "registry.local:5000",
            ),
        ] {
            let registry: Registry = registry.parse().unwrap();
            assert_eq!(registry.directory(), directory);
            assert_eq!(registry.server().as_deref(), server);
            assert_eq!(registry.credentials_host(), credentials);
        }
        for bad in ["", "a b", "https://", "user@host", "host/path", "ftp://host"] {
            assert!(bad.parse::<Registry>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn endpoints() {
        for (good, path) in [
            ("https://mirror.example.com", false),
            ("https://mirror.example.com/", false),
            ("mirror.local:5000/v2/hub", true),
            ("http://10.0.0.1:5000", false),
        ] {
            assert_eq!(good.parse::<Endpoint>().unwrap().has_path(), path, "{good}");
        }
        for bad in [
            "",
            "ftp://mirror",
            "https://u:p@mirror",
            "https://mirror?x=1",
            "https://",
        ] {
            assert!(bad.parse::<Endpoint>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn mirrors_render_hosts_files() {
        let settings = parse(
            r#"
[[mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com", "https://cache.example.com/v2/hub"]

[[mirrors]]
registry = "*"
endpoint = ["https://global.example.com"]
"#,
        )
        .unwrap();
        let files = hosts_files(&settings);
        assert_eq!(files[0].0, "docker.io");
        let docker: toml::Table = files[0].1.parse().unwrap();
        assert_eq!(docker["server"].as_str(), Some("https://registry-1.docker.io"));
        let mirror = &docker["host"]["https://mirror.example.com"];
        assert_eq!(mirror["capabilities"], toml::Value::from(vec!["pull", "resolve"]));
        assert!(mirror.get("override_path").is_none());
        assert_eq!(
            docker["host"]["https://cache.example.com/v2/hub"]["override_path"].as_bool(),
            Some(true)
        );
        // Hosts are tried in the order given.
        assert!(files[0].1.find("mirror.example.com").unwrap() < files[0].1.find("cache.example.com").unwrap());
        let default: toml::Table = files[1].1.parse().unwrap();
        assert_eq!(files[1].0, "_default");
        assert!(default.get("server").is_none());

        // Bottlerocket's former table form.
        let table = parse("[mirrors]\n\"docker.io\" = [\"https://mirror.example.com\"]\n").unwrap();
        assert_eq!(table.mirrors[0].registry.as_str(), "docker.io");
    }

    #[test]
    fn credentials_render_cri_configs_and_stay_secret() {
        let settings = parse(
            r#"
[[credentials]]
registry = "docker.io"
username = "me"
password = "hunter2"

[[credentials]]
registry = "registry.example.com:5000"
auth = "bWU6aHVudGVyMg=="

[[creds]]
registry = "ghcr.io"
identitytoken = "token-1"
"#,
        );
        // `creds` is an alias of the whole list, not mixable with `credentials`.
        assert!(settings.is_err());
        let settings = parse(
            r#"
[[credentials]]
registry = "docker.io"
username = "me"
password = "hunter2"

[[credentials]]
registry = "registry.example.com:5000"
auth = "bWU6aHVudGVyMg=="

[[credentials]]
registry = "ghcr.io"
identitytoken = "token-1"
"#,
        )
        .unwrap();
        let configs = cri_auth_configs(&settings);
        assert_eq!(
            configs["registry-1.docker.io"]["auth"]["password"].as_str(),
            Some("hunter2")
        );
        assert_eq!(configs["registry-1.docker.io"]["auth"]["username"].as_str(), Some("me"));
        assert_eq!(
            configs["registry.example.com:5000"]["auth"]["auth"].as_str(),
            Some("bWU6aHVudGVyMg==")
        );
        assert_eq!(configs["ghcr.io"]["auth"]["identitytoken"].as_str(), Some("token-1"));

        let shown = toml::to_string(&settings).unwrap();
        for secret in ["hunter2", "bWU6aHVudGVyMg==", "token-1"] {
            assert!(!shown.contains(secret), "{secret} shown in {shown}");
        }
        assert!(shown.contains("username = \"me\""));
        assert!(!format!("{settings:?}").contains("hunter2"));
    }

    #[test]
    fn rejects_invalid_settings() {
        for (text, why) in [
            (
                "[[credentials]]\nregistry = \"x\"\nusername = \"me\"\n",
                "username without password",
            ),
            (
                "[[credentials]]\nregistry = \"x\"\nauth = \"bWU=\"\n",
                "auth without a colon",
            ),
            (
                "[[credentials]]\nregistry = \"x\"\nauth = \"!!\"\n",
                "auth that is not base64",
            ),
            (
                "[[credentials]]\nregistry = \"x\"\nidentitytoken = \"t\"\nauth = \"bWU6aHVudGVyMg==\"\n",
                "two forms",
            ),
            (
                "[[credentials]]\nregistry = \"*\"\nidentitytoken = \"t\"\n",
                "credentials for every registry",
            ),
            (
                "[[credentials]]\nregistry = \"x\"\npassword = \"a\\nb\"\nusername = \"me\"\n",
                "multi-line password",
            ),
            (
                "[[credentials]]\nregistry = \"x\"\nidentitytoken = \"t\"\n[[credentials]]\nregistry = \"x\"\nidentitytoken = \"u\"\n",
                "twice the same registry",
            ),
            ("[[mirrors]]\nregistry = \"docker.io\"\nendpoint = []\n", "no endpoint"),
            ("[[mirrors]]\nregistry = \"docker.io\"\n", "no endpoint key"),
            (
                "[[mirrors]]\nregistry = \"docker.io\"\nendpoint = [\"ftp://m\"]\n",
                "bad endpoint",
            ),
            (
                "[[mirrors]]\nregistry = \"docker.io\"\nendpoints = [\"https://m\"]\n",
                "unknown key",
            ),
        ] {
            assert!(parse(text).is_err(), "{why} accepted");
        }
    }
}

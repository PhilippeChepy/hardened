//! `[settings.container-registry]`: registry mirrors and credentials, for every image pull of the
//! machine (kubelet's pods and workloads), with Bottlerocket's keys and value formats.
//! machine-controller renders them for containerd as Bottlerocket's `thar-be-registries` does.

use std::collections::BTreeMap;
use std::collections::btree_map::Entry;
use std::fmt;

use controllers_helpers::base64_text;
use controllers_helpers::{InvalidValue, NonEmpty, PrivateKey, validated_string};
use http::Uri;
use http::uri::Authority;
use serde::{Deserialize, Serialize};

/// containerd's name for Docker Hub's registry, which `docker.io` references resolve to.
const DOCKER_HUB: &str = "docker.io";
/// The host Docker Hub's registry answers on.
const DOCKER_HUB_REGISTRY: &str = "registry-1.docker.io";

/// `[settings.container-registry]`. Keyed by registry, so each has one set of mirrors and one
/// credential: registries are held in one form only ([`Registry`]), so two keys are two hosts.
///
/// Written as Bottlerocket writes it: `[[mirrors]]` of `registry` and `endpoint` (or its former
/// table of registry to endpoints), and `[[credentials]]` (or `[[creds]]`) of `registry` and
/// `username` and `password`, `auth`, or `identitytoken`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RegistryTables", into = "RegistryTables")]
pub struct RegistrySettings {
    /// The mirrors of every registry without mirrors of its own (`registry = "*"`).
    pub default_mirrors: Option<NonEmpty<Endpoint>>,
    /// The mirrors of each registry.
    pub mirrors: BTreeMap<Registry, Mirror>,
    /// What containerd sends each registry host.
    pub credentials: BTreeMap<Registry, Auth>,
}

/// The mirrors of a registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mirror {
    /// How the registry itself is reached, after its mirrors (`http://` or `https://` before the
    /// registry; by default, HTTP on port 80 and HTTPS otherwise, as `thar-be-registries` infers
    /// it). Docker Hub is always reached over HTTPS.
    pub scheme: Scheme,
    /// Tried in order, before the registry itself.
    pub endpoints: NonEmpty<Endpoint>,
}

/// How containerd reaches a registry.
#[allow(missing_docs, reason = "self-explanatory variants")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    /// Its name in URLs.
    #[must_use]
    fn as_str(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

/// What containerd sends a registry (its CRI plugin's `AuthConfig`), in exactly one form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Auth {
    /// `username` and `password`.
    Basic {
        /// The user's name.
        username: SingleLine,
        /// The user's password.
        password: Secret,
    },
    /// `auth`: the same, as Docker's `config.json` holds them.
    Encoded(EncodedAuth),
    /// `identitytoken`: an OAuth refresh token.
    IdentityToken(Secret),
}

impl Auth {
    /// The `Authorization` header sending these credentials, `Basic <base64>`, secret included;
    /// `None` for an identity token, which only an OAuth token exchange can use.
    #[must_use]
    pub fn basic_authorization(&self) -> Option<String> {
        let encoded = match self {
            Self::Basic { username, password } => {
                base64_text::encode(format!("{}:{}", username.as_str(), password.expose()))
            }
            Self::Encoded(auth) => auth.normalized().to_owned(),
            Self::IdentityToken(_) => return None,
        };
        Some(format!("Basic {encoded}"))
    }
}

validated_string!(
    /// A registry: `<host>[:<port>]`, lowercase, Docker Hub's being `docker.io`. One form per
    /// registry: containerd's directory and credentials of each are distinct. User-data may
    /// write it with a scheme, which only matters to a mirrored registry ([`Mirror::scheme`]).
    Registry,
    "registry",
    check_registry
);

fn check_registry(registry: &str) -> Result<(), &'static str> {
    const REASON: &str = "must be [http://|https://]<host>[:<port>], lowercase";
    let authority: Authority = registry.parse().map_err(|_| REASON)?;
    let host = authority.host();
    let characters_ok = host
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '-'))
        || host.starts_with('[');
    if registry.is_empty() || registry.contains(['@', '/', '_']) || !characters_ok {
        Err(REASON)
    } else if host == DOCKER_HUB_REGISTRY {
        Err("Docker Hub is docker.io")
    } else {
        Ok(())
    }
}

impl Registry {
    /// The registry of `text`, and the scheme it is written with, if any.
    fn with_scheme(text: &str) -> Result<(Self, Option<Scheme>), InvalidValue> {
        let (scheme, host) = if let Some(host) = text.strip_prefix("http://") {
            (Some(Scheme::Http), host)
        } else if let Some(host) = text.strip_prefix("https://") {
            (Some(Scheme::Https), host)
        } else {
            (None, text)
        };
        Ok((host.parse()?, scheme))
    }

    /// How it is reached when user-data does not say: HTTP on port 80, HTTPS otherwise.
    #[must_use]
    fn default_scheme(&self) -> Scheme {
        if self.as_str().ends_with(":80") {
            Scheme::Http
        } else {
            Scheme::Https
        }
    }

    /// Its directory under containerd's `config_path`: `<host>_<port>_` with a port.
    #[must_use]
    pub fn directory(&self) -> String {
        match self.as_str().rsplit_once(':') {
            Some((host, port)) if !port.ends_with(']') => format!("{host}_{port}_"),
            _ => self.as_str().to_owned(),
        }
    }

    /// `server` of its `hosts.toml`, reached with `scheme`: Docker Hub's for `docker.io`.
    #[must_use]
    pub fn server(&self, scheme: Scheme) -> String {
        match self.as_str() {
            DOCKER_HUB => format!("https://{DOCKER_HUB_REGISTRY}"),
            host => format!("{}://{host}", scheme.as_str()),
        }
    }

    /// The host containerd looks credentials up with: the one it contacts, so Docker Hub's for
    /// `docker.io`.
    #[must_use]
    pub fn credentials_host(&self) -> &str {
        match self.as_str() {
            DOCKER_HUB => DOCKER_HUB_REGISTRY,
            host => host,
        }
    }
}

/// [`RegistrySettings`] as Bottlerocket writes them.
#[derive(Default, Serialize, Deserialize)]
#[serde(
    rename_all = "kebab-case",
    deny_unknown_fields,
    expecting = "a table of `mirrors` and `credentials`"
)]
struct RegistryTables {
    #[serde(default, skip_serializing_if = "MirrorTables::is_empty")]
    mirrors: MirrorTables,
    #[serde(default, alias = "creds", skip_serializing_if = "Vec::is_empty")]
    credentials: Vec<CredentialTable>,
}

/// `mirrors`: `[[mirrors]]` tables, or (Bottlerocket's former form) a table of registry to
/// endpoints. Their values are checked once read, so that errors name them rather than the form.
#[derive(Serialize, Deserialize)]
#[serde(
    untagged,
    expecting = "mirrors must be `[[mirrors]]` tables of `registry` and `endpoint` (no other \
                 key), or a table of registry to endpoints"
)]
enum MirrorTables {
    List(Vec<MirrorTable>),
    Former(BTreeMap<String, Vec<String>>),
}

impl Default for MirrorTables {
    fn default() -> Self {
        Self::List(Vec::new())
    }
}

impl MirrorTables {
    fn is_empty(&self) -> bool {
        match self {
            Self::List(list) => list.is_empty(),
            Self::Former(table) => table.is_empty(),
        }
    }
}

/// A `[[mirrors]]` table: a registry (as written, or `*`) and its endpoints.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MirrorTable {
    registry: String,
    endpoint: Vec<String>,
}

/// A `[[credentials]]` table: a registry (never `*`; its scheme, if written, does not matter)
/// and exactly one of `username` and `password`, `auth`, or `identitytoken`.
#[derive(Default, Serialize, Deserialize)]
#[serde(
    deny_unknown_fields,
    expecting = "a table of `registry` and its credentials"
)]
struct CredentialTable {
    registry: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    username: Option<SingleLine>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<Secret>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth: Option<EncodedAuth>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identitytoken: Option<Secret>,
}

impl TryFrom<RegistryTables> for RegistrySettings {
    type Error = String;

    fn try_from(tables: RegistryTables) -> Result<Self, String> {
        let mirrors = match tables.mirrors {
            MirrorTables::List(list) => list,
            MirrorTables::Former(table) => table
                .into_iter()
                .map(|(registry, endpoint)| MirrorTable { registry, endpoint })
                .collect(),
        };
        let mut settings = Self::default();
        for mirror in mirrors {
            settings.insert_mirror(mirror)?;
        }
        for credential in tables.credentials {
            settings.insert_credential(credential)?;
        }
        Ok(settings)
    }
}

impl RegistrySettings {
    /// The mirrors as user-data writes them, `*`'s first: each registry, with a scheme when it is
    /// not the default one, and its endpoints.
    pub(crate) fn written_mirrors(&self) -> impl Iterator<Item = (String, Vec<String>)> {
        let strings =
            |endpoints: &NonEmpty<Endpoint>| endpoints.iter().map(ToString::to_string).collect();
        let default = self
            .default_mirrors
            .iter()
            .map(move |endpoints| ("*".to_owned(), strings(endpoints)));
        let mirrors = self.mirrors.iter().map(move |(registry, mirror)| {
            let written =
                if mirror.scheme == registry.default_scheme() || registry.as_str() == DOCKER_HUB {
                    registry.to_string()
                } else {
                    format!("{}://{registry}", mirror.scheme.as_str())
                };
            (written, strings(&mirror.endpoints))
        });
        default.chain(mirrors)
    }

    /// Adds the mirrors of a `[[mirrors]]` table, rejecting a registry given twice.
    fn insert_mirror(&mut self, table: MirrorTable) -> Result<(), String> {
        let MirrorTable { registry, endpoint } = table;
        let endpoints = endpoint
            .into_iter()
            .map(|endpoint| endpoint.parse())
            .collect::<Result<Vec<Endpoint>, _>>()
            .map_err(|e| e.to_string())?;
        let endpoints = NonEmpty::from_vec(endpoints)
            .ok_or_else(|| format!("mirrors of {registry}: give one endpoint at least"))?;
        let twice = || format!("mirrors of {registry}: the registry is given twice");
        if registry == "*" {
            return match self.default_mirrors.replace(endpoints) {
                None => Ok(()),
                Some(_) => Err(twice()),
            };
        }
        let (parsed, scheme) = Registry::with_scheme(&registry).map_err(|e| e.to_string())?;
        if parsed.as_str() == DOCKER_HUB && scheme == Some(Scheme::Http) {
            return Err("mirrors of docker.io: Docker Hub is reached over HTTPS".to_owned());
        }
        let scheme = scheme.unwrap_or_else(|| parsed.default_scheme());
        match self.mirrors.entry(parsed) {
            Entry::Vacant(entry) => {
                entry.insert(Mirror { scheme, endpoints });
                Ok(())
            }
            Entry::Occupied(_) => Err(twice()),
        }
    }

    /// Adds the credential of a `[[credentials]]` table, rejecting a registry given twice.
    fn insert_credential(&mut self, table: CredentialTable) -> Result<(), String> {
        if table.registry == "*" {
            return Err("credentials are for one registry, not \"*\"".to_owned());
        }
        let (registry, _) = Registry::with_scheme(&table.registry).map_err(|e| e.to_string())?;
        let auth = match (
            table.username,
            table.password,
            table.auth,
            table.identitytoken,
        ) {
            (Some(username), Some(password), None, None) => Auth::Basic { username, password },
            (None, None, Some(auth), None) => Auth::Encoded(auth),
            (None, None, None, Some(token)) => Auth::IdentityToken(token),
            _ => {
                return Err(format!(
                    "credentials of {registry}: give username and password, auth, or \
                     identitytoken"
                ));
            }
        };
        match self.credentials.entry(registry) {
            Entry::Vacant(entry) => {
                entry.insert(auth);
                Ok(())
            }
            Entry::Occupied(entry) => Err(format!(
                "credentials of {}: the registry is given twice",
                entry.key()
            )),
        }
    }
}

/// As user-data writes them: `[[mirrors]]`, `*` first, and `[[credentials]]`, secrets included.
impl From<RegistrySettings> for RegistryTables {
    fn from(settings: RegistrySettings) -> Self {
        let mirrors = settings
            .written_mirrors()
            .map(|(registry, endpoint)| MirrorTable { registry, endpoint })
            .collect();
        let credentials = settings
            .credentials
            .into_iter()
            .map(|(registry, auth)| {
                let mut table = CredentialTable {
                    registry: registry.into(),
                    ..CredentialTable::default()
                };
                match auth {
                    Auth::Basic { username, password } => {
                        table.username = Some(username);
                        table.password = Some(password);
                    }
                    Auth::Encoded(encoded) => table.auth = Some(encoded),
                    Auth::IdentityToken(token) => table.identitytoken = Some(token),
                }
                table
            })
            .collect();
        Self {
            mirrors: MirrorTables::List(mirrors),
            credentials,
        }
    }
}

validated_string!(
    /// A mirror endpoint: `[http://|https://]<host>[:<port>][/<path>]`.
    Endpoint,
    "registry mirror endpoint",
    check_endpoint
);

fn check_endpoint(endpoint: &str) -> Result<(), &'static str> {
    let uri: Uri = if endpoint.contains("://") {
        endpoint.parse()
    } else {
        format!("https://{endpoint}").parse()
    }
    .map_err(|_| "must be a URL")?;
    match (uri.scheme_str(), uri.authority()) {
        (Some("http" | "https"), Some(authority))
            if !authority.as_str().contains('@') && uri.query().is_none() =>
        {
            Ok(())
        }
        _ => Err("must be an http or https URL with a host, and no credentials or query"),
    }
}

impl Endpoint {
    /// Whether it has a path, which replaces the registry's `/v2` path (`override_path`).
    #[must_use]
    pub fn has_path(&self) -> bool {
        let text = self.as_str();
        let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
        rest.split_once('/')
            .is_some_and(|(_, path)| !path.is_empty())
    }

    /// The host it is reached on, `<host>[:<port>]`: containerd looks its credentials up with it.
    #[must_use]
    pub fn host(&self) -> &str {
        let text = self.as_str();
        let rest = text.split_once("://").map_or(text, |(_, rest)| rest);
        rest.split_once('/').map_or(rest, |(host, _)| host)
    }
}

validated_string!(
    /// A non-empty value on a single line.
    SingleLine,
    "value",
    check_single_line
);

fn check_single_line(text: &str) -> Result<(), &'static str> {
    if text.is_empty() || text.contains(|c: char| c.is_control()) {
        Err("must be a non-empty single line")
    } else {
        Ok(())
    }
}

/// A secret single-line value. Like [`PrivateKey`], never displayed or logged, but serialized as
/// itself.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Secret(String);

impl Secret {
    /// The value, to write containerd's configuration. The only way to read it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Secret {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        if check_single_line(&text).is_err() {
            return Err(InvalidValue::new(
                "secret",
                PrivateKey::REDACTED,
                "must be a non-empty single line",
            ));
        }
        Ok(Self(text))
    }
}

impl From<Secret> for String {
    fn from(secret: Secret) -> Self {
        secret.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(PrivateKey::REDACTED)
    }
}

/// The base64 of `<username>:<password>`, a [`Secret`], as user-data holds it and encoded again
/// when parsed: user-data's may hold whitespace.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct EncodedAuth {
    text: Secret,
    normalized: Secret,
}

impl EncodedAuth {
    /// The base64 text, as user-data holds it.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.text.expose()
    }

    /// The base64 text without whitespace, for containerd's configuration.
    #[must_use]
    pub fn normalized(&self) -> &str {
        self.normalized.expose()
    }
}

impl TryFrom<String> for EncodedAuth {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let invalid = || {
            InvalidValue::new(
                "registry auth",
                PrivateKey::REDACTED,
                "must be the base64 of <username>:<password>",
            )
        };
        let decoded = base64_text::decode(text.as_bytes())
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .filter(|decoded| decoded.contains(':'))
            .ok_or_else(invalid)?;
        Ok(Self {
            normalized: Secret::try_from(base64_text::encode(decoded))?,
            text: Secret::try_from(text)?,
        })
    }
}

impl From<EncodedAuth> for String {
    fn from(auth: EncodedAuth) -> Self {
        auth.text.into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<RegistrySettings, toml::de::Error> {
        toml::from_str(text)
    }

    fn rejected(text: &str) -> String {
        parse(text).unwrap_err().to_string()
    }

    #[test]
    fn registries() {
        for (registry, directory, server, credentials) in [
            (
                "docker.io",
                "docker.io",
                "https://registry-1.docker.io",
                "registry-1.docker.io",
            ),
            (
                "registry.example.com:5000",
                "registry.example.com_5000_",
                "https://registry.example.com:5000",
                "registry.example.com:5000",
            ),
            (
                "registry.example.com:80",
                "registry.example.com_80_",
                "http://registry.example.com:80",
                "registry.example.com:80",
            ),
        ] {
            let registry: Registry = registry.parse().unwrap();
            assert_eq!(registry.directory(), directory);
            assert_eq!(registry.server(registry.default_scheme()), server);
            assert_eq!(registry.credentials_host(), credentials);
        }
    }

    #[test]
    fn registries_have_one_form() {
        for bad in [
            "",
            "*",
            "a b",
            "https://registry.example.com",
            "Registry.example.com",
            "user@host",
            "host/path",
            "my_host",
            "registry-1.docker.io",
        ] {
            assert!(bad.parse::<Registry>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn endpoints() {
        for (good, path, host) in [
            ("https://mirror.example.com", false, "mirror.example.com"),
            ("https://mirror.example.com/", false, "mirror.example.com"),
            ("mirror.local:5000/v2/hub", true, "mirror.local:5000"),
            ("http://10.0.0.1:5000", false, "10.0.0.1:5000"),
        ] {
            let endpoint: Endpoint = good.parse().unwrap();
            assert_eq!(endpoint.has_path(), path, "{good}");
            assert_eq!(endpoint.host(), host, "{good}");
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
    fn mirrors_round_trip() {
        let settings = parse(
            r#"
[[mirrors]]
registry = "*"
endpoint = ["https://global.example.com"]

[[mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com", "https://cache.example.com/v2/hub"]

[[mirrors]]
registry = "http://registry.local:5000"
endpoint = ["http://10.0.0.1:5000"]

[[mirrors]]
registry = "https://registry.example.com:80"
endpoint = ["https://mirror.example.com"]
"#,
        )
        .unwrap();
        assert_eq!(settings.default_mirrors.as_ref().unwrap().iter().count(), 1);
        assert_eq!(settings.mirrors["docker.io"].endpoints.iter().count(), 2);
        let local = &settings.mirrors["registry.local:5000"];
        assert_eq!(local.scheme, Scheme::Http);
        let registry: Registry = "registry.local:5000".parse().unwrap();
        assert_eq!(registry.server(local.scheme), "http://registry.local:5000");
        let example = &settings.mirrors["registry.example.com:80"];
        assert_eq!(example.scheme, Scheme::Https, "the scheme written wins");

        let text = toml::to_string(&settings).unwrap();
        assert!(
            text.contains("registry = \"http://registry.local:5000\""),
            "{text}"
        );
        assert!(text.contains("registry = \"docker.io\""), "{text}");
        assert_eq!(parse(&text).unwrap(), settings);
    }

    #[test]
    fn mirrors_take_bottlerocket_former_table() {
        let table = parse(
            "[mirrors]\n\"docker.io\" = [\"https://mirror.example.com\"]\n\
             \"*\" = [\"https://global.example.com\"]\n",
        )
        .unwrap();
        assert_eq!(
            table.mirrors["docker.io"].endpoints.first().as_str(),
            "https://mirror.example.com"
        );
        assert!(table.default_mirrors.is_some());
    }

    #[test]
    fn credentials_as_authorization_headers() {
        let settings = parse(
            r#"
[[credentials]]
registry = "docker.io"
username = "me"
password = "hunter2"

[[credentials]]
registry = "quay.io"
auth = "bWU6 aHVudGVyMg=="

[[credentials]]
registry = "ghcr.io"
identitytoken = "token-1"
"#,
        )
        .unwrap();
        let header = |registry: &str| settings.credentials[registry].basic_authorization();
        assert_eq!(
            header("docker.io").as_deref(),
            Some("Basic bWU6aHVudGVyMg==")
        );
        assert_eq!(header("quay.io").as_deref(), Some("Basic bWU6aHVudGVyMg=="));
        assert_eq!(header("ghcr.io"), None);
    }

    #[test]
    fn credentials_round_trip_and_stay_out_of_logs() {
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
registry = "https://ghcr.io"
identitytoken = "token-1"
"#,
        )
        .unwrap();
        assert!(matches!(
            &settings.credentials["docker.io"],
            Auth::Basic { username, password }
                if username.as_str() == "me" && password.expose() == "hunter2"
        ));
        assert!(matches!(
            &settings.credentials["registry.example.com:5000"],
            Auth::Encoded(auth) if auth.expose() == "bWU6aHVudGVyMg=="
        ));
        assert!(matches!(
            &settings.credentials["ghcr.io"],
            Auth::IdentityToken(token) if token.expose() == "token-1"
        ));

        let text = toml::to_string(&settings).unwrap();
        assert_eq!(
            parse(&text).unwrap(),
            settings,
            "serialized with the secrets"
        );
        let shown = format!("{settings:?}");
        for secret in ["hunter2", "bWU6aHVudGVyMg==", "token-1"] {
            assert!(!shown.contains(secret), "{secret} shown in {shown}");
        }
    }

    #[test]
    fn creds_is_an_alias() {
        let creds = parse("[[creds]]\nregistry = \"ghcr.io\"\nidentitytoken = \"t\"\n").unwrap();
        assert_eq!(creds.credentials.len(), 1);
    }

    #[test]
    fn rejects_credentials_without_exactly_one_form() {
        for text in [
            "[[credentials]]\nregistry = \"x\"\nusername = \"me\"\n",
            "[[credentials]]\nregistry = \"x\"\n",
            "[[credentials]]\nregistry = \"x\"\nidentitytoken = \"t\"\n\
             auth = \"bWU6aHVudGVyMg==\"\n",
        ] {
            assert!(
                rejected(text).contains("give username and password"),
                "{text}"
            );
        }
    }

    #[test]
    fn rejects_credentials_for_every_registry() {
        let error = rejected("[[credentials]]\nregistry = \"*\"\nidentitytoken = \"t\"\n");
        assert!(error.contains("not \"*\""), "{error}");
    }

    #[test]
    fn rejects_a_registry_given_twice() {
        for text in [
            "[[credentials]]\nregistry = \"x\"\nidentitytoken = \"t\"\n\
             [[credentials]]\nregistry = \"https://x\"\nidentitytoken = \"u\"\n",
            "[[mirrors]]\nregistry = \"x:5000\"\nendpoint = [\"https://m\"]\n\
             [[mirrors]]\nregistry = \"http://x:5000\"\nendpoint = [\"https://n\"]\n",
            "[[mirrors]]\nregistry = \"*\"\nendpoint = [\"https://m\"]\n\
             [[mirrors]]\nregistry = \"*\"\nendpoint = [\"https://n\"]\n",
        ] {
            assert!(rejected(text).contains("given twice"), "{text}");
        }
    }

    #[test]
    fn rejects_a_mirror_without_endpoints() {
        for text in [
            "[[mirrors]]\nregistry = \"docker.io\"\nendpoint = []\n",
            "[[mirrors]]\nregistry = \"docker.io\"\n",
        ] {
            assert!(parse(text).is_err(), "{text}");
        }
    }

    #[test]
    fn rejects_docker_hub_over_http() {
        let error =
            rejected("[[mirrors]]\nregistry = \"http://docker.io\"\nendpoint = [\"https://m\"]\n");
        assert!(error.contains("HTTPS"), "{error}");
    }

    #[test]
    fn rejects_unknown_keys() {
        for text in [
            "[[credentials]]\nregistry = \"x\"\nidentity-token = \"t\"\n",
            "[proxies]\n",
        ] {
            assert!(rejected(text).contains("unknown field"), "{text}");
        }
        let error =
            rejected("[[mirrors]]\nregistry = \"docker.io\"\nendpoints = [\"https://m\"]\n");
        assert!(error.contains("no other key"), "{error}");
    }

    #[test]
    fn encoded_auth_holds_a_user_and_password() {
        for bad in ["bWU=", "!!"] {
            let error = EncodedAuth::try_from(bad.to_owned()).unwrap_err();
            assert!(
                !error.to_string().contains(bad),
                "the secret is echoed: {error}"
            );
        }
    }
}

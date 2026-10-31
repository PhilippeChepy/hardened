//! containerd's configuration, `/run/containerd/config.toml`, which its service runs with: the
//! image's, plus what user-data adds: the registry mirrors and basic credentials (`hosts.toml`
//! files under `config_path`, which every pull reads), and the credentials again in the CRI
//! plugin's `configs`, for Kubernetes, identity tokens included.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::Context;
use controllers_helpers::NonEmpty;
use controllers_helpers::atomic_file;
use machine_controller::Auth;
use machine_controller::Endpoint;
use machine_controller::Registry;
use machine_controller::RegistrySettings;
use rustix::fs::Gid;
use rustix::fs::Uid;
use tracing::error;
use tracing::warn;

/// The image's configuration.
const BASE_CONFIG: &str = "/usr/share/hardened/containerd/config.toml";
/// containerd's state directory, holding its socket and configuration.
const RUN_DIR: &str = "/run/containerd";
/// What containerd runs with: the image's configuration and the registry credentials.
const CONFIG: &str = "/run/containerd/config.toml";
/// `config_path` of the CRI images plugin (in the image's configuration).
const HOSTS_DIR: &str = "/run/containerd/certs.d";
const CRI_IMAGES: &str = "io.containerd.cri.v1.images";

/// Writes containerd's configuration for `registry`. If it cannot be, writes the image's
/// unchanged, so containerd still starts, without mirrors or credentials.
pub fn configure(registry: &RegistrySettings) {
    for (registry, auth) in &registry.credentials {
        if matches!(auth, Auth::IdentityToken(_)) {
            warn!(
                %registry,
                "an identity token only applies to Kubernetes' pulls: workloads pull from this \
                 registry without credentials"
            );
        }
    }
    let Err(e) = write_config(registry) else {
        return;
    };
    error!("cannot apply settings.container-registry, containerd runs without it: {e:#}");
    let copied = fs::read(BASE_CONFIG)
        .and_then(|base| atomic_file::write(Path::new(CONFIG), &base, 0o600))
        .with_context(|| format!("copying {BASE_CONFIG} to {CONFIG}"));
    if let Err(e) = copied {
        error!("containerd has no configuration: {e:#}");
    }
}

fn write_config(registry: &RegistrySettings) -> anyhow::Result<()> {
    // Owned by root, with the mode containerd creates it with.
    fs::create_dir_all(RUN_DIR).context(RUN_DIR)?;
    rustix::fs::chown(RUN_DIR, Some(Uid::ROOT), Some(Gid::ROOT)).context(RUN_DIR)?;
    fs::set_permissions(RUN_DIR, Permissions::from_mode(0o711)).context(RUN_DIR)?;
    for hosts in hosts_files(registry) {
        let dir = Path::new(HOSTS_DIR).join(&hosts.directory);
        fs::create_dir_all(&dir).with_context(|| dir.display().to_string())?;
        // It may hold credentials.
        atomic_file::write(&dir.join("hosts.toml"), hosts.contents.as_bytes(), 0o600)
            .with_context(|| dir.display().to_string())?;
    }
    let base = fs::read_to_string(BASE_CONFIG).context(BASE_CONFIG)?;
    let config = generate(&base, cri_auth_configs(registry))?;
    // It holds the registry credentials.
    atomic_file::write(Path::new(CONFIG), config.as_bytes(), 0o600).context(CONFIG)
}

/// containerd's host configuration of a registry.
struct HostsFile {
    /// Its directory under `config_path`.
    directory: String,
    /// The `hosts.toml` file.
    contents: String,
}

/// containerd's host configuration (`<config_path>/<directory>/hosts.toml`) of `*`'s mirrors
/// (`_default`) and of each registry with mirrors or basic credentials: the mirrors, for pulling
/// and resolving, then the registry itself (or, for `*`, the registry an image names). Every
/// pull reads them, `ctr`'s (workloads) as well as CRI's (Kubernetes): a host's credentials are
/// its `Authorization` header there.
///
/// A registry with credentials but no mirrors of its own keeps `*`'s, which its directory would
/// otherwise hide, and has no `server`: containerd reaches it as it would without the file.
#[must_use]
fn hosts_files(settings: &RegistrySettings) -> Vec<HostsFile> {
    // By the host containerd contacts, as CRI's `configs` are.
    let authorizations: BTreeMap<&str, String> = settings
        .credentials
        .iter()
        .filter_map(|(registry, auth)| {
            Some((registry.credentials_host(), auth.basic_authorization()?))
        })
        .collect();
    let default = settings
        .default_mirrors
        .as_ref()
        .map(|endpoints| HostsFile {
            directory: "_default".to_owned(),
            contents: hosts_toml(None, None, Some(endpoints), &authorizations),
        });
    let credentials = settings
        .credentials
        .keys()
        .filter(|registry| authorizations.contains_key(registry.credentials_host()));
    let registries: BTreeSet<&Registry> = settings.mirrors.keys().chain(credentials).collect();
    let files = registries.into_iter().map(|registry| {
        let mirror = settings.mirrors.get(registry);
        let server = mirror.map(|mirror| registry.server(mirror.scheme));
        let endpoints = mirror.map_or(settings.default_mirrors.as_ref(), |mirror| {
            Some(&mirror.endpoints)
        });
        let authorization = authorizations.get(registry.credentials_host());
        HostsFile {
            directory: registry.directory(),
            contents: hosts_toml(
                server.as_deref(),
                authorization.map(String::as_str),
                endpoints,
                &authorizations,
            ),
        }
    });
    default.into_iter().chain(files).collect()
}

/// A `hosts.toml` file: the registry (`server`, else the directory's), with the `authorization`
/// header, tried after the `endpoints`, each with its host's header in `authorizations`.
///
/// Written by hand: containerd tries the hosts in the order of the file, which a `toml::Table`
/// (sorted) would not keep.
#[must_use]
fn hosts_toml(
    server: Option<&str>,
    authorization: Option<&str>,
    endpoints: Option<&NonEmpty<Endpoint>>,
    authorizations: &BTreeMap<&str, String>,
) -> String {
    // A TOML basic string, quoting and escaping as needed.
    let quoted = |text: &str| toml::Value::from(text).to_string();
    let header = |contents: &mut String, table: &str, authorization: &str| {
        contents.push_str(&format!(
            "\n[{table}]\nAuthorization = {}\n",
            quoted(authorization)
        ));
    };
    let mut contents =
        String::from("# Generated by machine-controller from settings.container-registry.\n");
    if let Some(server) = server {
        contents.push_str(&format!("server = {}\n", quoted(server)));
    }
    if let Some(authorization) = authorization {
        header(&mut contents, "header", authorization);
    }
    for endpoint in endpoints.into_iter().flatten() {
        let host = quoted(endpoint.as_str());
        contents.push_str(&format!(
            "\n[host.{host}]\ncapabilities = [\"pull\", \"resolve\"]\n"
        ));
        if endpoint.has_path() {
            contents.push_str("override_path = true\n");
        }
        // Right after its host: containerd takes another `host` table for a new host.
        if let Some(authorization) = authorizations.get(endpoint.host()) {
            header(&mut contents, &format!("host.{host}.header"), authorization);
        }
    }
    contents
}

/// The `configs` table of containerd's CRI registry configuration: the credentials of each host,
/// which CRI pulls use when the request carries none (kubelet's pods without image pull
/// secrets). Identity tokens only work there: `hosts.toml` holds no OAuth exchange.
#[must_use]
fn cri_auth_configs(settings: &RegistrySettings) -> toml::Table {
    let mut configs = toml::Table::new();
    for (registry, credential) in &settings.credentials {
        let mut auth = toml::Table::new();
        match credential {
            Auth::Basic { username, password } => {
                auth.insert("username".into(), username.as_str().into());
                auth.insert("password".into(), password.expose().into());
            }
            Auth::Encoded(encoded) => {
                auth.insert("auth".into(), encoded.expose().into());
            }
            Auth::IdentityToken(token) => {
                auth.insert("identitytoken".into(), token.expose().into());
            }
        }
        let mut config = toml::Table::new();
        config.insert("auth".into(), auth.into());
        configs.insert(registry.credentials_host().to_owned(), config.into());
    }
    configs
}

/// `base` (read from [`BASE_CONFIG`]) with the CRI plugin's registry `configs` (credentials, by
/// host) set to `configs`. Relative `imports` are made absolute: containerd resolves them against
/// the directory of the file it reads, which is no longer the image's.
///
/// `configs` is deprecated in containerd 2 (until 2.7) in favor of `config_path`, whose
/// `hosts.toml` only holds headers: it remains the way to give CRI pulls an identity token. With
/// containerd 2.7, a credential helper takes its place.
fn generate(base: &str, configs: toml::Table) -> anyhow::Result<String> {
    let mut config: toml::Table = base
        .parse()
        .context("parsing the image's containerd configuration")?;
    if let Some(toml::Value::Array(imports)) = config.get_mut("imports") {
        let dir = Path::new(BASE_CONFIG).parent().unwrap_or(Path::new("/"));
        for import in imports.iter_mut() {
            if let toml::Value::String(path) = import
                && Path::new(path).is_relative()
            {
                *path = dir.join(&*path).to_string_lossy().into_owned();
            }
        }
    }
    if !configs.is_empty() {
        let mut table = &mut config;
        for key in ["plugins", CRI_IMAGES, "registry"] {
            table = table
                .entry(key)
                .or_insert_with(|| toml::Table::new().into())
                .as_table_mut()
                .context("the image's containerd configuration has no CRI registry table")?;
        }
        table.insert("configs".into(), configs.into());
    }
    Ok(format!(
        "# Generated by machine-controller from {BASE_CONFIG} and settings.container-registry.\n\
         {config}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = r#"version = 3
root = "/var/lib/containerd"

[plugins.'io.containerd.cri.v1.images']
  snapshotter = "overlayfs"

  [plugins.'io.containerd.cri.v1.images'.registry]
    config_path = "/run/containerd/certs.d"

[plugins.'io.containerd.cri.v1.runtime']
  enable_selinux = false
"#;

    fn generated(base: &str, configs: toml::Table) -> toml::Table {
        generate(base, configs).unwrap().parse().unwrap()
    }

    #[test]
    fn credentials_are_added_to_the_cri_registry() {
        let mut configs = toml::Table::new();
        configs.insert("ghcr.io".into(), toml::Table::new().into());
        let config = generated(BASE, configs.clone());
        let registry = &config["plugins"][CRI_IMAGES]["registry"];
        assert_eq!(registry["configs"], toml::Value::from(configs));
        assert_eq!(registry["config_path"].as_str(), Some(HOSTS_DIR));
        assert_eq!(
            config["plugins"]["io.containerd.cri.v1.runtime"]["enable_selinux"].as_bool(),
            Some(false)
        );
    }

    #[test]
    fn mirrors_render_hosts_files() {
        let settings: RegistrySettings = toml::from_str(
            r#"
[[mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com", "https://cache.example.com/v2/hub"]

[[mirrors]]
registry = "*"
endpoint = ["https://global.example.com"]

[[mirrors]]
registry = "http://registry.local:5000"
endpoint = ["https://mirror.example.com"]
"#,
        )
        .unwrap();
        let files = hosts_files(&settings);
        // `*` comes first.
        assert_eq!(files[1].directory, "docker.io");
        let docker: toml::Table = files[1].contents.parse().unwrap();
        assert_eq!(
            docker["server"].as_str(),
            Some("https://registry-1.docker.io")
        );
        let mirror = &docker["host"]["https://mirror.example.com"];
        assert_eq!(
            mirror["capabilities"],
            toml::Value::from(vec!["pull", "resolve"])
        );
        assert!(mirror.get("override_path").is_none());
        assert_eq!(
            docker["host"]["https://cache.example.com/v2/hub"]["override_path"].as_bool(),
            Some(true)
        );
        let docker = &files[1].contents;
        assert!(
            docker.find("mirror.example.com").unwrap() < docker.find("cache.example.com").unwrap(),
            "hosts are tried in the order given"
        );
        let default: toml::Table = files[0].contents.parse().unwrap();
        assert_eq!(files[0].directory, "_default");
        assert!(default.get("server").is_none());
        let local: toml::Table = files[2].contents.parse().unwrap();
        assert_eq!(files[2].directory, "registry.local_5000_");
        assert_eq!(local["server"].as_str(), Some("http://registry.local:5000"));
    }

    #[test]
    fn credentials_render_authorization_headers() {
        let settings: RegistrySettings = toml::from_str(
            r#"
[[mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com", "https://cache.example.com/v2/hub"]

[[mirrors]]
registry = "*"
endpoint = ["https://mirror.example.com"]

[[credentials]]
registry = "docker.io"
username = "me"
password = "hunter2"

[[credentials]]
registry = "mirror.example.com"
auth = "bWlycm9yOnMzY3IzdA=="

[[credentials]]
registry = "registry.example.com:5000"
username = "puller"
password = "s3cr3t"

[[credentials]]
registry = "ghcr.io"
identitytoken = "token-1"
"#,
        )
        .unwrap();
        let files = hosts_files(&settings);
        let directories: Vec<&str> = files.iter().map(|file| file.directory.as_str()).collect();
        // ghcr.io's identity token has no header: no file.
        assert_eq!(
            directories,
            [
                "_default",
                "docker.io",
                "mirror.example.com",
                "registry.example.com_5000_"
            ]
        );
        let parsed: Vec<toml::Table> = files
            .iter()
            .map(|file| file.contents.parse().unwrap())
            .collect();
        let mirror = Some("Basic bWlycm9yOnMzY3IzdA==");

        // `*`'s mirrors: the mirror's header, none for the image's registry.
        let default = &parsed[0];
        assert!(default.get("header").is_none());
        assert_eq!(
            default["host"]["https://mirror.example.com"]["header"]["Authorization"].as_str(),
            mirror
        );

        // Docker Hub's, then the mirror's; the cache has no credentials.
        let docker = &parsed[1];
        assert_eq!(
            docker["header"]["Authorization"].as_str(),
            Some("Basic bWU6aHVudGVyMg==")
        );
        assert_eq!(
            docker["host"]["https://mirror.example.com"]["header"]["Authorization"].as_str(),
            mirror
        );
        assert!(
            docker["host"]["https://cache.example.com/v2/hub"]
                .get("header")
                .is_none()
        );

        // Credentials without mirrors: no `server` (containerd's default), `*`'s mirrors kept.
        for (registry, authorization) in [
            (&parsed[2], mirror),
            (&parsed[3], Some("Basic cHVsbGVyOnMzY3IzdA==")),
        ] {
            assert!(registry.get("server").is_none());
            assert_eq!(registry["header"]["Authorization"].as_str(), authorization);
            assert!(registry["host"].get("https://mirror.example.com").is_some());
        }
        // A header is its host's only table: containerd reads a new host from every other one.
        let docker = &files[1].contents;
        assert_eq!(docker.matches("[host.").count(), 3);
        assert!(
            docker
                .find("[host.\"https://mirror.example.com\".header]")
                .unwrap()
                < docker
                    .find("[host.\"https://cache.example.com/v2/hub\"]")
                    .unwrap()
        );
    }

    #[test]
    fn credentials_without_mirrors_render_a_hosts_file() {
        let settings: RegistrySettings = toml::from_str(
            r#"
[[credentials]]
registry = "quay.io"
auth = "cHVsbGVyOnMzY3IzdA=="
"#,
        )
        .unwrap();
        let files = hosts_files(&settings);
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].directory, "quay.io");
        let quay: toml::Table = files[0].contents.parse().unwrap();
        assert_eq!(
            quay,
            toml::from_str("header.Authorization = \"Basic cHVsbGVyOnMzY3IzdA==\"").unwrap()
        );
    }

    #[test]
    fn credentials_render_cri_configs() {
        let settings: RegistrySettings = toml::from_str(
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
        assert_eq!(
            configs["registry-1.docker.io"]["auth"]["username"].as_str(),
            Some("me")
        );
        assert_eq!(
            configs["registry.example.com:5000"]["auth"]["auth"].as_str(),
            Some("bWU6aHVudGVyMg==")
        );
        assert_eq!(
            configs["ghcr.io"]["auth"]["identitytoken"].as_str(),
            Some("token-1")
        );
    }

    #[test]
    fn without_credentials_the_configuration_is_the_image_s() {
        assert_eq!(
            generated(BASE, toml::Table::new()),
            BASE.parse::<toml::Table>().unwrap()
        );
    }

    #[test]
    fn relative_imports_point_to_the_image() {
        let base = format!("imports = [\"conf.d/pause.toml\", \"/etc/containerd/x.toml\"]\n{BASE}");
        let config = generated(&base, toml::Table::new());
        let pause = Path::new(BASE_CONFIG)
            .parent()
            .unwrap()
            .join("conf.d/pause.toml");
        assert_eq!(
            config["imports"],
            toml::Value::from(vec![pause.to_str().unwrap(), "/etc/containerd/x.toml"])
        );
    }
}

//! `hctl settings`' output: the settings `Machine.GetSettings` returns, as user-data TOML.
//!
//! The keys and value formats are user-data's (`machine-controller`): PEM in base64, defaults
//! left out. `[settings.kubernetes]` and the containers are written by their controllers' own
//! types, as user-data reads them. Secrets, which the server leaves empty, show as `<redacted>`.

use std::collections::HashMap;

use anyhow::Context as _;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kubelet_controller::KubeletConfig;
use kubelet_controller::kubelet;
use machine_apiproxy::apiproxy;
use machine_controller::machine;
use machine_controller::machine::registry_credential::Auth;
use machine_controller::machine::{ModuleLoad, RegistryCredential};
use storage_controller::storage::Encryption;
use time_controller::time;
use toml::{Table, Value};
use workload_controller::ContainerSettings;
use workload_controller::workloads::DeclaredWorkloads;

/// What a secret shows as.
const REDACTED: &str = "<redacted>";

/// A valid bootstrap token, standing for the one `GetSettings` leaves empty until redacted.
const PLACEHOLDER_TOKEN: &str = "000000.0000000000000000";

/// user-data's defaults, left out.
const DEFAULT_LISTEN: &str = "0.0.0.0:7443";

/// The settings as user-data's `[settings]` table; empty, and shown as nothing, when every
/// setting has its default.
///
/// # Errors
///
/// When the server's `kubernetes` or `containers` are not valid settings.
pub fn table(settings: &machine::Settings) -> anyhow::Result<Table> {
    let mut groups = Table::new();
    insert_table(&mut groups, "kernel", kernel(settings));
    if let Some(hostname) = &settings.hostname {
        let mut network = Table::new();
        insert_string(&mut network, "hostname", hostname);
        insert_table(&mut groups, "network", network);
    }
    if let Some(dns) = &settings.dns {
        let mut table = Table::new();
        insert_strings(&mut table, "name-servers", &dns.name_servers);
        insert_strings(&mut table, "search-list", &dns.search_list);
        insert_table(&mut groups, "dns", table);
    }
    let mut ntp = Table::new();
    insert_strings(&mut ntp, "time-servers", &settings.time_servers);
    insert_table(&mut groups, "ntp", ntp);
    if let Some(kubelet) = &settings.kubernetes {
        let kubernetes = kubernetes(kubelet).context("settings.kubernetes")?;
        groups.insert("kubernetes".to_owned(), Value::Table(kubernetes));
    }
    insert_table(&mut groups, "container-registry", registry(settings));
    insert_table(&mut groups, "hardened", hardened(settings)?);
    let mut root = Table::new();
    insert_table(&mut root, "settings", groups);
    Ok(root)
}

/// `[settings.kernel]`.
#[must_use]
fn kernel(settings: &machine::Settings) -> Table {
    let mut kernel = Table::new();
    insert_table(&mut kernel, "sysctl", string_table(&settings.sysctl));
    let mut modules = Table::new();
    for module in &settings.kernel_modules {
        let mut flags = Table::new();
        match module.load() {
            ModuleLoad::Never => {
                flags.insert("allowed".to_owned(), Value::Boolean(false));
            }
            // Declared even with the defaults.
            ModuleLoad::AsDependency => {
                flags.insert("allowed".to_owned(), Value::Boolean(true));
            }
            ModuleLoad::AtBoot => {
                flags.insert("autoload".to_owned(), Value::Boolean(true));
            }
            ModuleLoad::Unspecified => {}
        }
        modules.insert(module.name.clone(), Value::Table(flags));
    }
    insert_table(&mut kernel, "modules", modules);
    kernel
}

/// `[settings.kubernetes]`, the bootstrap token redacted.
fn kubernetes(kubelet: &kubelet::Kubelet) -> anyhow::Result<Table> {
    let message = kubelet::Kubelet {
        bootstrap_token: PLACEHOLDER_TOKEN.to_owned(),
        ..kubelet.clone()
    };
    let mut table = Table::try_from(KubeletConfig::try_from(message)?)?;
    insert_string(&mut table, "bootstrap-token", REDACTED);
    Ok(table)
}

/// `[settings.container-registry]`.
#[must_use]
fn registry(settings: &machine::Settings) -> Table {
    let mut table = Table::new();
    let mirrors = settings
        .registry_mirrors
        .iter()
        .map(|mirror| {
            let mut entry = Table::new();
            insert_string(&mut entry, "registry", &mirror.registry);
            insert_strings(&mut entry, "endpoint", &mirror.endpoints);
            entry
        })
        .collect();
    insert_tables(&mut table, "mirrors", mirrors);
    let credentials = settings
        .registry_credentials
        .iter()
        .map(credential_table)
        .collect();
    insert_tables(&mut table, "credentials", credentials);
    table
}

/// A `[[settings.container-registry.credentials]]` table, the secret redacted whether or not the
/// server left it empty.
#[must_use]
fn credential_table(credential: &RegistryCredential) -> Table {
    let mut table = Table::new();
    insert_string(&mut table, "registry", &credential.registry);
    match &credential.auth {
        Some(Auth::Basic(basic)) => {
            insert_string(&mut table, "username", &basic.username);
            insert_string(&mut table, "password", REDACTED);
        }
        Some(Auth::Encoded(_)) => insert_string(&mut table, "auth", REDACTED),
        Some(Auth::IdentityToken(_)) => insert_string(&mut table, "identitytoken", REDACTED),
        None => {}
    }
    table
}

/// `[settings.hardened]`.
fn hardened(settings: &machine::Settings) -> anyhow::Result<Table> {
    let mut table = Table::new();
    if let Some(api) = &settings.api {
        table.insert("api".to_owned(), Value::Table(api_table(api)));
    }
    if let Some(storage) = &settings.storage
        && storage.encryption() == Encryption::Tpm
    {
        let mut storage = Table::new();
        insert_string(&mut storage, "encryption", "tpm");
        table.insert("storage".to_owned(), Value::Table(storage));
    }
    let source = match settings.time_source() {
        time::Source::Auto => None,
        time::Source::Ptp => Some("ptp"),
        time::Source::Ntp => Some("ntp"),
    };
    if let Some(source) = source {
        let mut time = Table::new();
        insert_string(&mut time, "source", source);
        table.insert("time".to_owned(), Value::Table(time));
    }
    if let Some(declared) = &settings.containers {
        let declared = containers(declared).context("settings.hardened.containers")?;
        insert_table(&mut table, "containers", declared);
    }
    Ok(table)
}

/// `[settings.hardened.api]`.
#[must_use]
fn api_table(api: &apiproxy::Configuration) -> Table {
    let mut table = Table::new();
    if api.listen != DEFAULT_LISTEN {
        insert_string(&mut table, "listen", &api.listen);
    }
    if let Some(tls) = &api.tls {
        insert_base64(&mut table, "client-ca", &tls.client_ca);
        insert_base64(&mut table, "certificate", &tls.certificate);
        insert_string(&mut table, "private-key", REDACTED);
    }
    table
}

/// `[settings.hardened.containers]`.
fn containers(containers: &DeclaredWorkloads) -> anyhow::Result<Table> {
    let mut table = Table::new();
    for workload in &containers.workloads {
        let (name, settings) = ContainerSettings::try_from_proto(workload.clone())?;
        table.insert(name.into(), Value::Table(Table::try_from(settings)?));
    }
    Ok(table)
}

#[must_use]
fn string_table(map: &HashMap<String, String>) -> Table {
    map.iter()
        .map(|(key, value)| (key.clone(), Value::String(value.clone())))
        .collect()
}

/// Inserts `table` unless it is empty.
fn insert_table(parent: &mut Table, key: &str, table: Table) {
    if !table.is_empty() {
        parent.insert(key.to_owned(), Value::Table(table));
    }
}

/// Inserts an array of tables unless it is empty.
fn insert_tables(parent: &mut Table, key: &str, tables: Vec<Table>) {
    if !tables.is_empty() {
        let tables = tables.into_iter().map(Value::Table).collect();
        parent.insert(key.to_owned(), Value::Array(tables));
    }
}

/// Inserts `value` unless it is empty.
fn insert_string(table: &mut Table, key: &str, value: &str) {
    if !value.is_empty() {
        table.insert(key.to_owned(), Value::String(value.to_owned()));
    }
}

/// Inserts the base64 of `value` (PEM, a manifest), as user-data holds it, unless it is empty.
fn insert_base64(table: &mut Table, key: &str, value: &str) {
    insert_string(table, key, &STANDARD.encode(value));
}

/// Inserts `values` unless there are none.
fn insert_strings(table: &mut Table, key: &str, values: &[String]) {
    if !values.is_empty() {
        let values = values.iter().cloned().map(Value::String).collect();
        table.insert(key.to_owned(), Value::Array(values));
    }
}

#[cfg(test)]
mod tests {
    use kubelet_controller::testing::full_toml;
    use workload_controller::workloads;
    use workload_controller::workloads::{DeclaredWorkload, RestartPolicy};

    use super::*;

    fn full_settings() -> machine::Settings {
        machine::Settings {
            sysctl: HashMap::from([("net.ipv4.ip_forward".into(), "1".into())]),
            kernel_modules: vec![
                machine::KernelModule {
                    name: "wireguard".into(),
                    load: ModuleLoad::AtBoot.into(),
                },
                machine::KernelModule {
                    name: "sctp".into(),
                    load: ModuleLoad::Never.into(),
                },
            ],
            hostname: Some("web-1".into()),
            dns: Some(network_controller::network::Configuration {
                name_servers: vec!["192.0.2.53".into()],
                search_list: vec!["corp.example.com".into()],
            }),
            time_servers: vec!["time.example.com".into()],
            containers: None,
            kubernetes: None,
            registry_mirrors: vec![machine::RegistryMirror {
                registry: "docker.io".into(),
                endpoints: vec!["https://mirror.example.com".into()],
            }],
            registry_credentials: vec![
                machine::RegistryCredential {
                    registry: "mirror.example.com".into(),
                    auth: Some(Auth::Basic(machine::registry_credential::Basic {
                        username: "puller".into(),
                        password: String::new(),
                    })),
                },
                machine::RegistryCredential {
                    registry: "docker.io".into(),
                    auth: Some(Auth::Encoded(String::new())),
                },
                machine::RegistryCredential {
                    registry: "ghcr.io".into(),
                    auth: Some(Auth::IdentityToken(String::new())),
                },
            ],
            api: Some(apiproxy::Configuration {
                listen: "[::]:7443".into(),
                tls: Some(apiproxy::TlsIdentity {
                    client_ca: "CLIENT CA".into(),
                    certificate: "CERT".into(),
                    private_key: String::new(),
                }),
            }),
            storage: Some(storage_controller::storage::Configuration {
                encryption: Encryption::Tpm.into(),
            }),
            time_source: time::Source::Ptp.into(),
        }
    }

    #[test]
    fn renders_every_setting_as_user_data() {
        let expected = r#"[[settings.container-registry.credentials]]
password = "<redacted>"
registry = "mirror.example.com"
username = "puller"

[[settings.container-registry.credentials]]
auth = "<redacted>"
registry = "docker.io"

[[settings.container-registry.credentials]]
identitytoken = "<redacted>"
registry = "ghcr.io"

[[settings.container-registry.mirrors]]
endpoint = ["https://mirror.example.com"]
registry = "docker.io"

[settings.dns]
name-servers = ["192.0.2.53"]
search-list = ["corp.example.com"]

[settings.hardened.api]
certificate = "Q0VSVA=="
client-ca = "Q0xJRU5UIENB"
listen = "[::]:7443"
private-key = "<redacted>"

[settings.hardened.storage]
encryption = "tpm"

[settings.hardened.time]
source = "ptp"

[settings.kernel.modules.sctp]
allowed = false

[settings.kernel.modules.wireguard]
autoload = true

[settings.kernel.sysctl]
"net.ipv4.ip_forward" = "1"

[settings.network]
hostname = "web-1"

[settings.ntp]
time-servers = ["time.example.com"]
"#;
        let rendered = table(&full_settings()).unwrap().to_string();
        assert_eq!(rendered, expected, "{rendered}");
    }

    #[test]
    fn renders_kubernetes_as_user_data_with_the_token_redacted() {
        let config: KubeletConfig = toml::from_str(&full_toml()).unwrap();
        let settings = machine::Settings {
            kubernetes: Some(kubelet::Kubelet {
                bootstrap_token: String::new(),
                ..config.clone().into()
            }),
            ..machine::Settings::default()
        };
        let rendered = table(&settings).unwrap();
        let mut expected = Table::try_from(config).unwrap();
        expected.insert("bootstrap-token".into(), REDACTED.into());
        assert_eq!(rendered["settings"]["kubernetes"], Value::Table(expected));

        let invalid = machine::Settings {
            kubernetes: Some(kubelet::Kubelet::default()),
            ..machine::Settings::default()
        };
        let error = table(&invalid).unwrap_err();
        assert!(format!("{error:#}").contains("api_server"), "{error:#}");
    }

    #[test]
    fn renders_containers_as_user_data() {
        let workloads = vec![
            DeclaredWorkload {
                name: "web".into(),
                enabled: true,
                spec: Some(workloads::WorkloadSpec {
                    image: "docker.io/library/nginx:1.29".into(),
                    command: vec!["nginx".into(), "-g".into(), "daemon off;".into()],
                    env: HashMap::from([("NGINX_PORT".into(), "8080".into())]),
                    privileged: Some(workloads::Privileged {
                        host_root: "/host".into(),
                    }),
                    restart: RestartPolicy::OnFailure.into(),
                    mounts: vec![workloads::Mount {
                        source: "/var/lib/web".into(),
                        destination: "/usr/share/nginx/html".into(),
                        read_only: true,
                    }],
                    console: true,
                }),
            },
            DeclaredWorkload {
                name: "idle".into(),
                enabled: false,
                spec: Some(workloads::WorkloadSpec {
                    image: "docker.io/library/busybox:latest".into(),
                    ..workloads::WorkloadSpec::default()
                }),
            },
        ];
        let settings = machine::Settings {
            containers: Some(DeclaredWorkloads { workloads }),
            ..machine::Settings::default()
        };
        let expected = r#"[settings.hardened.containers.idle]
console = false
enabled = false
image = "docker.io/library/busybox:latest"
privileged = false
restart = "always"

[settings.hardened.containers.web]
command = ["nginx", "-g", "daemon off;"]
console = true
enabled = true
image = "docker.io/library/nginx:1.29"
restart = "on-failure"

[settings.hardened.containers.web.env]
NGINX_PORT = "8080"

[[settings.hardened.containers.web.mounts]]
destination = "/usr/share/nginx/html"
read-only = true
source = "/var/lib/web"

[settings.hardened.containers.web.privileged]
host-root = "/host"
"#;
        let rendered = table(&settings).unwrap().to_string();
        assert_eq!(rendered, expected, "{rendered}");
    }

    #[test]
    fn leaves_defaults_out() {
        assert_eq!(
            table(&machine::Settings::default()).unwrap().to_string(),
            ""
        );
        let defaults = machine::Settings {
            dns: Some(network_controller::network::Configuration::default()),
            storage: Some(storage_controller::storage::Configuration {
                encryption: Encryption::None.into(),
            }),
            ..machine::Settings::default()
        };
        assert!(table(&defaults).unwrap().is_empty());
        let api = machine::Settings {
            api: Some(apiproxy::Configuration {
                listen: DEFAULT_LISTEN.into(),
                tls: None,
            }),
            ..machine::Settings::default()
        };
        assert_eq!(
            table(&api).unwrap().to_string(),
            "[settings.hardened.api]\n"
        );
    }
}

//! mTLS connection to `machine-apiproxy`, and call error reporting.

use std::error::Error;
use std::fmt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context as _;
use clap::Args;
use rustls_pki_types::ServerName;
use tonic::Status;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Identity};

use crate::args::Endpoint;
use crate::pki;

/// How to reach and authenticate to `machine-apiproxy`.
#[derive(Args)]
pub struct ConnectionArgs {
    /// machine-apiproxy endpoint: host, host:port or https://host[:port] (default port 7443).
    #[arg(long, short, env = "HCTL_ENDPOINT", global = true)]
    endpoint: Option<Endpoint>,
    /// Directory holding ca.pem, client.pem and client-key.pem [default: ~/.config/hardened].
    #[arg(long, env = "HCTL_CONFIG_DIR", global = true)]
    config_dir: Option<PathBuf>,
    /// CA certificate the server must chain to [default: <config-dir>/ca.pem].
    #[arg(long, env = "HCTL_CA", global = true)]
    ca: Option<PathBuf>,
    /// Client certificate [default: <config-dir>/client.pem].
    #[arg(long, env = "HCTL_CERT", global = true)]
    cert: Option<PathBuf>,
    /// Client private key [default: <config-dir>/client-key.pem].
    #[arg(long, env = "HCTL_KEY", global = true)]
    key: Option<PathBuf>,
    /// Name the server certificate must match [default: the endpoint host].
    #[arg(long, env = "HCTL_TLS_SERVER_NAME", global = true, value_parser = server_name)]
    tls_server_name: Option<ServerName<'static>>,
}

/// Parses `--tls-server-name`.
fn server_name(s: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(s.to_owned()).map_err(|e| format!("{s:?}: {e}"))
}

impl ConnectionArgs {
    /// Reads `explicit`, or else `name` in the configuration directory.
    fn read(&self, explicit: Option<&Path>, name: &str) -> anyhow::Result<Vec<u8>> {
        let path = match (explicit, &self.config_dir) {
            (Some(path), _) => path.to_owned(),
            (None, Some(dir)) => dir.join(name),
            (None, None) => default_config_dir()?.join(name),
        };
        std::fs::read(&path).with_context(|| format!("reading {}", path.display()))
    }
}

/// `$XDG_CONFIG_HOME/hardened`, falling back to `~/.config/hardened`.
fn default_config_dir() -> anyhow::Result<PathBuf> {
    let base = match std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
        Some(dir) => PathBuf::from(dir),
        None => {
            let home = std::env::var_os("HOME").context("HOME is not set")?;
            PathBuf::from(home).join(".config")
        }
    };
    Ok(base.join("hardened"))
}

/// Connects to `machine-apiproxy`, authenticating with the client certificate.
pub async fn connect(args: &ConnectionArgs) -> anyhow::Result<Channel> {
    let endpoint = args
        .endpoint
        .as_ref()
        .context("no endpoint: pass --endpoint or set HCTL_ENDPOINT")?;
    let ca = Certificate::from_pem(args.read(args.ca.as_deref(), pki::CA_CERT)?);
    let identity = Identity::from_pem(
        args.read(args.cert.as_deref(), pki::CLIENT_CERT)?,
        args.read(args.key.as_deref(), pki::CLIENT_KEY)?,
    );
    let mut tls = ClientTlsConfig::new().ca_certificate(ca).identity(identity);
    if let Some(name) = &args.tls_server_name {
        tls = tls.domain_name(name.to_str());
    }
    // Not `crate::args::Endpoint`, which validated the URI.
    tonic::transport::Endpoint::from(endpoint.uri().clone())
        .tls_config(tls)?
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await
        .with_context(|| format!("connecting to {endpoint}"))
}

/// A failed call, shown as `Code: message` followed by its transport cause, if any.
#[derive(Debug)]
pub struct CallFailed(pub Status);

impl fmt::Display for CallFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.0.code(), self.0.message())
    }
}

impl Error for CallFailed {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

/// Unwraps unary call results.
pub trait CallExt<T> {
    /// The response's message, or the call's failure.
    fn into_result(self) -> Result<T, CallFailed>;
}

impl<T> CallExt<T> for Result<tonic::Response<T>, Status> {
    fn into_result(self) -> Result<T, CallFailed> {
        self.map(tonic::Response::into_inner).map_err(CallFailed)
    }
}

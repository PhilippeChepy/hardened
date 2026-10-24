//! dust-api: serves the dust API remotely over mTLS (see the library docs).

use std::io::IsTerminal;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use clap::Parser;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "Remote mTLS front of the dust API")]
struct Cli {
    /// Address to accept clients on.
    #[arg(long, env = "DUST_API_LISTEN", default_value = "0.0.0.0:7443")]
    listen: SocketAddr,
    /// dust-init's control socket.
    #[arg(long, env = "DUST_API_SOCKET", default_value = dust_proto::CONTROL_SOCKET)]
    socket: PathBuf,
    /// Directory holding client-ca.pem, cert.pem and key.pem.
    #[arg(long, env = "DUST_API_TLS_DIR", default_value = "/run/dust-api/tls")]
    tls_dir: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let logs = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(filter);
    if std::io::stderr().is_terminal() {
        logs.init();
    } else {
        // Run by dust-init, which timestamps the lines it forwards to its own log.
        logs.with_ansi(false).without_time().init();
    }
    let cli = Cli::parse();

    let tls = dust_api::tls::server_config(&cli.tls_dir)
        .with_context(|| format!("loading TLS material from {}", cli.tls_dir.display()))?;
    let listener = TcpListener::bind(cli.listen)
        .await
        .with_context(|| format!("binding {}", cli.listen))?;
    let mut terminate = signal(SignalKind::terminate())?;
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };

    tracing::info!(listen = %cli.listen, socket = %cli.socket.display(), "serving");
    dust_api::serve(listener, Arc::new(tls), cli.socket, shutdown).await;
    Ok(())
}

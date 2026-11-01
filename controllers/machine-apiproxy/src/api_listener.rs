//! The mTLS listener, restarted for each new configuration.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use machine_apiproxy::ApiConfig;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use crate::server;
use crate::tls;

/// The mTLS listener, forwarding to the machine-controller on its `upstream` socket.
pub struct ApiListener {
    upstream: PathBuf,
    running: Mutex<Option<Running>>,
}

/// A listener serving.
struct Running {
    config: ApiConfig,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl ApiListener {
    /// A listener that serves once configured.
    #[must_use]
    pub fn new(upstream: PathBuf) -> Self {
        Self {
            upstream,
            running: Mutex::new(None),
        }
    }

    /// Serves with `config`, replacing the listener of an earlier one; the same one again changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// When the TLS identity is unusable (the listener of an earlier one then keeps serving), or
    /// its address cannot be listened on.
    pub async fn apply(&self, config: ApiConfig) -> anyhow::Result<()> {
        let mut running = self.running.lock().await;
        if running
            .as_ref()
            .is_some_and(|running| running.config == config)
        {
            return Ok(());
        }
        let tls = Arc::new(tls::server_config(&config).context("loading the TLS identity")?);
        if let Some(previous) = running.take() {
            previous.stop().await;
        }
        let listener = TcpListener::bind(config.listen)
            .await
            .with_context(|| format!("listening on {}", config.listen))?;
        let (stop, stopped) = oneshot::channel();
        let upstream = self.upstream.clone();
        let task = tokio::spawn(async move {
            let stopped = async {
                // A dropped sender stops too.
                let _ = stopped.await;
            };
            server::serve(listener, tls, &upstream, stopped).await;
        });
        tracing::info!(listen = %config.listen, "serving");
        *running = Some(Running { config, stop, task });
        Ok(())
    }

    /// Stops serving, once the calls in flight are drained.
    pub async fn stop(&self) {
        if let Some(running) = self.running.lock().await.take() {
            running.stop().await;
        }
    }
}

impl Running {
    async fn stop(self) {
        // An error means the task is already over.
        let _ = self.stop.send(());
        if let Err(e) = self.task.await {
            tracing::error!(error = %e, "the listener's task failed");
        }
    }
}

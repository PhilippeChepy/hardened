//! kubelet-controller: writes kubelet's configuration, credentials and static pods from what
//! machine-controller gives it, then enables kubelet's service, or keeps it disabled. It serves
//! `KubeletController` on its activated `api` socket, and is ready once configured.

mod controller;
mod rendered;
mod state;

use std::env;
use std::io;
use std::path::PathBuf;

use anyhow::Context;
use kubelet_controller::kubelet::kubelet_controller_server::KubeletControllerServer;
use libserviced::activation::Sockets;
use rustix::mount::MountPropagationFlags;
use tokio::signal::unix::SignalKind;
use tonic::transport::Server;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::controller::Controller;

fn main() -> anyhow::Result<()> {
    let filter = env::var("RUST_LOG")
        .ok()
        .and_then(|directives| directives.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    // serviced timestamps the lines it writes to the service's log.
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .finish()
        .with(filter)
        .init();
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the runtime")?
        .block_on(run())
}

async fn run() -> anyhow::Result<()> {
    let socket = Sockets::from_env()
        .context("taking the sockets serviced passed")?
        .take("api")
        .context("taking the api socket")?;
    // Volumes with `Bidirectional` or `HostToContainer` propagation (CSI drivers, Cilium's bpffs)
    // need shared host mounts; kubelet itself only shares /var/lib/kubelet.
    rustix::mount::mount_change(
        c"/",
        MountPropagationFlags::SHARED | MountPropagationFlags::REC,
    )
    .context("making the mounts shared")?;
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;
    let mut terminate =
        tokio::signal::unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;

    let controller = Controller::new(
        serviced.clone(),
        PathBuf::from("/"),
        PathBuf::from(state::PATH),
    );
    controller.restore().await;
    let router = Server::builder().add_service(KubeletControllerServer::new(controller));
    tracing::info!("serving");
    libserviced::authorization::serve(router, socket, serviced, async move {
        terminate.recv().await;
        tracing::info!("terminated");
    })
    .await
    .context("serving")
}

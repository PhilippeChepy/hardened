//! nvidia-controller: at boot, when the PCI bus has NVIDIA GPUs, loads NVIDIA's open kernel
//! modules (signed, from the verity root) and makes their device nodes, which the driver does not
//! make itself; then serves the GPUs' state on its `api` socket, and partitions them (MIG) as
//! machine-controller configures it. Ready once set up, GPUs or not.
//!
//! `nvidia-controller --driver /usr/lib/nvidia/<version>`: the driver the image ships.

mod device_nodes;
mod driver;
mod mig_layout;
mod nvidia_service;
mod nvidia_smi;
mod partitioner;
mod pci_gpu;
mod setup;

use std::env;
use std::ffi::OsString;
use std::io;
use std::path::PathBuf;

use anyhow::Context as _;
use anyhow::bail;
use libserviced::activation::Sockets;
use libserviced::notify;
use nvidia_controller::nvidia::nvidia_controller_server::NvidiaControllerServer;
use tokio::signal::unix;
use tokio::signal::unix::SignalKind;
use tonic::transport::Server;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;

use crate::driver::Driver;
use crate::nvidia_service::NvidiaService;
use crate::nvidia_smi::NvidiaSmi;
use crate::partitioner::Partitioner;

/// Where the GPUs' MIG instances are recorded.
const MIG_RECORDS: &str = "/run/nvidia-controller/mig";

#[tokio::main(flavor = "current_thread")]
async fn main() -> anyhow::Result<()> {
    let filter = env::var("RUST_LOG")
        .ok()
        .and_then(|directives| directives.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    // serviced timestamps the lines it forwards to its own log.
    tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_ansi(false)
        .without_time()
        .with_target(false)
        .finish()
        .with(filter)
        .init();

    let driver = Driver::new(driver_dir(env::args_os().skip(1).collect())?);
    let mut sockets = Sockets::from_env().context("taking the sockets serviced passed")?;
    let api = sockets.take("api").context("taking the API's socket")?;
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;

    let partitioner = Partitioner::new(NvidiaSmi::new(driver.root()), PathBuf::from(MIG_RECORDS));
    let mut state = setup::run(&driver);
    if state.ready {
        partitioner.refresh(&mut state.gpus);
    }
    if let Err(error) = notify::ready() {
        tracing::warn!(%error, "cannot notify serviced");
    }
    let service = NvidiaService::new(state, partitioner);
    let router = Server::builder().add_service(NvidiaControllerServer::new(service));
    let mut terminate = unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;
    libserviced::authorization::serve(router, api, serviced, async move {
        terminate.recv().await;
        tracing::info!("terminated");
    })
    .await
    .context("serving")
}

/// The directory of `--driver <dir>`, the only arguments.
fn driver_dir(args: Vec<OsString>) -> anyhow::Result<PathBuf> {
    match <[OsString; 2]>::try_from(args) {
        Ok([flag, dir]) if flag == "--driver" => Ok(PathBuf::from(dir)),
        _ => bail!("usage: nvidia-controller --driver /usr/lib/nvidia/<version>"),
    }
}

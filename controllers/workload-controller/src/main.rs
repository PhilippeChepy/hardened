//! workload-controller: runs workloads as services of serviced, user-data's (configured by
//! machine-controller) in its runtime layer, the API's in its persistent layer. It serves
//! `WorkloadController` and `Workloads` on its activated `api` socket.

mod configuration;
mod controller;
mod defined_workload;
mod service_file;
mod workloads_service;

use std::env;
use std::io;
use std::path::PathBuf;

use anyhow::Context;
use libserviced::activation::Sockets;
use tokio::signal::unix::SignalKind;
use tonic::transport::Server;
use tracing::Level;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::SubscriberExt as _;
use tracing_subscriber::util::SubscriberInitExt as _;
use workload_controller::workload::workload_controller_server::WorkloadControllerServer;
use workload_controller::workloads::workloads_server::WorkloadsServer;

use crate::controller::Controller;
use crate::controller::SharedConfiguration;
use crate::workloads_service::WorkloadsService;

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
    let serviced = libserviced::connect()
        .await
        .context("connecting to serviced")?;
    let mut terminate =
        tokio::signal::unix::signal(SignalKind::terminate()).context("handling SIGTERM")?;

    let configuration = SharedConfiguration::default();
    let root = PathBuf::from("/");
    let controller = Controller::new(
        serviced.clone(),
        root.clone(),
        configuration.clone(),
        PathBuf::from(configuration::STATE),
    );
    controller.restore().await;
    let workloads = WorkloadsService::new(serviced.clone(), root, configuration);
    let router = Server::builder()
        .add_service(WorkloadControllerServer::new(controller))
        .add_service(WorkloadsServer::new(workloads));
    tracing::info!("serving");
    libserviced::authorization::serve(router, socket, serviced, async move {
        terminate.recv().await;
        tracing::info!("terminated");
    })
    .await
    .context("serving")
}

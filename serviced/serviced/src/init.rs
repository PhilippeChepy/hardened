//! serviced's life as PID 1: early setup, the supervisor until a power request, then the
//! reboot or power-off; after a failure of serviced itself, a reboot.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustix::fs::Mode;
use tokio::runtime;
use tokio::sync::mpsc;
use tracing::{error, info};

use crate::api_server;
use crate::caller;
use crate::kernel;
use crate::log_buffer::LogBuffer;
use crate::log_store;
use crate::log_store::LogStore;
use crate::logging;
use crate::mounts;
use crate::overview::Overview;
use crate::power;
use crate::power::PowerRequest;
use crate::process::Reaper;
use crate::serviced_service::ServicedService;
use crate::shutdown;
use crate::shutdown_locks::ShutdownLocks;
use crate::supervisor::Supervisor;

/// After a failure of serviced itself, the time left to read the console before the reboot.
const FAILURE_DELAY: Duration = Duration::from_secs(30);

/// Sets the machine up, runs the services until a power request, then carries it out.
pub fn run() -> ! {
    std::panic::set_hook(Box::new(|info| {
        logging::console_now(&format!("error: panic: {info}"));
    }));
    rustix::process::umask(Mode::from_raw_mode(0o022));

    if let Err(e) = mounts::mount_early().and_then(|()| mounts::create_dirs()) {
        logging::console(&format!("error: early mounts failed: {e:#}"));
        std::thread::sleep(FAILURE_DELAY);
        shutdown::finish(PowerRequest::Reboot);
    }
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let filter = cmdline
        .split_ascii_whitespace()
        .find_map(|arg| arg.strip_prefix("serviced.log="))
        .unwrap_or("info");
    let log = Arc::new(LogBuffer::new(
        log_store::SERVICED_LINES,
        log_store::SERVICED_BYTES,
    ));
    logging::init(filter, log.clone());
    // Before any service starts: no other kernel file may be loaded first.
    kernel::pin();
    kernel::apply_sysctls();

    let runtime = match runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("serviced")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            error!("cannot start the async runtime: {e}");
            std::thread::sleep(FAILURE_DELAY);
            shutdown::finish(PowerRequest::Reboot);
        }
    };

    let request = runtime.block_on(async {
        let reaper = match Reaper::start() {
            Ok(reaper) => reaper,
            Err(e) => {
                // No service started yet: nothing to stop.
                error!("serviced failed, rebooting soon: {e:#}");
                tokio::time::sleep(FAILURE_DELAY).await;
                return PowerRequest::Reboot;
            }
        };
        // In a task of its own: a panic there is caught, and the machine still shuts down.
        match tokio::spawn(supervise(log, reaper.clone())).await {
            Ok(Ok(request)) => request,
            Ok(Err(e)) => {
                error!("serviced failed: {e:#}");
                fail(&reaper).await
            }
            Err(e) => {
                error!("serviced's supervisor failed: {e}");
                fail(&reaper).await
            }
        }
    });
    shutdown::finish(request)
}

/// Serves the API and supervises the services until a power request, which it returns once they
/// stopped. `log` is serviced's own; `reaper` collects every process.
async fn supervise(log: Arc<LogBuffer>, reaper: Reaper) -> anyhow::Result<PowerRequest> {
    let kernel = rustix::system::uname()
        .release()
        .to_string_lossy()
        .into_owned();
    info!(kernel, "serviced starting");
    let (power_tx, power_rx) = mpsc::channel(4);
    power::watch(power_tx.clone())?;

    let logs = Arc::new(LogStore::new(log));
    let overview = Arc::new(Overview::default());
    let resolve = caller::resolver();
    let (commands_tx, commands_rx) = mpsc::unbounded_channel();
    let shutdown_locks = Arc::new(ShutdownLocks::default());
    let service = ServicedService {
        overview: overview.clone(),
        logs: logs.clone(),
        resolve: resolve.clone(),
        commands: commands_tx,
        power: power_tx,
        shutdown_locks: shutdown_locks.clone(),
    };
    // Without it, the services go on as far as they can: their calls fail.
    match api_server::bind(Path::new(libserviced::SOCKET)) {
        Ok(listener) => {
            tokio::spawn(api_server::serve(listener, service));
        }
        Err(e) => error!("serviced's API is unavailable: {e:#}"),
    }

    let supervisor = Supervisor::new(reaper, commands_rx, logs, overview, resolve, shutdown_locks);
    Ok(supervisor.run(power_rx).await)
}

/// After a failure of the supervisor, which stops the services otherwise: kills every process.
async fn fail(reaper: &Reaper) -> PowerRequest {
    error!("rebooting in {} seconds", FAILURE_DELAY.as_secs());
    tokio::time::sleep(FAILURE_DELAY).await;
    shutdown::terminate_all(reaper).await;
    PowerRequest::Reboot
}

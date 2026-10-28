//! Boot sequence, run as PID 1. Never returns: when the machine is asked to stop, workloads and
//! containerd are stopped, `/var` is unmounted and the kernel reboots or powers off. A failure
//! during boot is logged and followed by a reboot.

mod containerd;
mod kmod;
mod kubelet;
mod mounts;
mod service;
mod sysctl;

use std::io::Write as _;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::api::Api;
use crate::attestation::Tpm;
use crate::logging::{self, LogRing};
use crate::machine::{Machine, MachineInfo, PowerRequest};
use crate::ntp::{Ntp, Servers};
use crate::platform::{Metadata, Platform};
use crate::process::Reaper;
use crate::settings::{ApiSettings, DnsSettings, KubernetesSettings, Settings, UserData};
use crate::types::Hostname;
use crate::workloads::{self, Manager, Source};
use crate::{control, net, power, storage};

/// Time left to workloads to exit after SIGTERM when shutting down.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(20);
/// Pause between attempts to connect to containerd.
const CONNECT_RETRY: Duration = Duration::from_secs(10);
/// Time left to kubelet to exit after SIGTERM when shutting down; its pods are stopped next.
const KUBELET_GRACE: Duration = Duration::from_secs(10);

/// Who runs the pods: dust-init's workload manager, or kubelet. Not both: kubelet stops the pods
/// it does not know of.
enum Pods {
    Workloads(tokio::task::JoinHandle<()>),
    Kubelet(tokio::task::JoinHandle<service::Service>),
}

pub fn run() -> ! {
    std::panic::set_hook(Box::new(|info| {
        let _ = writeln!(std::io::stderr(), "dust-init: panic: {info}");
    }));

    if let Err(e) = mounts::mount_early() {
        let _ = writeln!(std::io::stderr(), "dust-init: error: early mounts failed: {e:#}");
        power::finish(PowerRequest::Reboot);
    }
    let cmdline = std::fs::read_to_string("/proc/cmdline").unwrap_or_default();
    let filter = cmdline
        .split_ascii_whitespace()
        .find_map(|arg| arg.strip_prefix("dust-init.log="))
        .unwrap_or("info");
    let logs = logging::init(filter);

    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .thread_name("dust-init")
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(e) => {
            error!("cannot start the async runtime: {e}");
            power::finish(PowerRequest::Reboot);
        }
    };

    let request = runtime.block_on(async {
        match boot(logs).await {
            Ok(request) => request,
            Err(e) => {
                error!("boot failed: {e:#}");
                error!("rebooting in 30 seconds");
                tokio::time::sleep(Duration::from_secs(30)).await;
                PowerRequest::Reboot
            }
        }
    });
    power::finish(request)
}

/// Boots the machine, then serves until a power request arrives; returns it once everything is
/// stopped.
async fn boot(logs: LogRing) -> anyhow::Result<PowerRequest> {
    let booted_at = SystemTime::now();
    let os_version = os_release_field("VERSION_ID").unwrap_or_else(|| "unknown".into());
    let kernel = rustix::system::uname().release().to_string_lossy().into_owned();
    info!("hardened {os_version} starting, kernel {kernel}");

    let reaper = Reaper::start()?;
    let (power_tx, mut power_rx) = mpsc::channel(4);
    power::watch(power_tx.clone())?;
    kmod::pin();
    sysctl::apply_defaults();
    set_hostname(&Hostname::localhost())?;

    let platform = Platform::detect();
    match platform {
        Some(platform) => info!(%platform, "platform detected"),
        None => warn!("unknown platform: no metadata source"),
    }

    let network = net::configure().await.unwrap_or_else(|e| {
        error!("network configuration failed: {e:#}");
        net::NetworkState::default()
    });

    for interface in &network.interfaces {
        match &interface.lease {
            Some(lease) => info!(
                interface = interface.name,
                address = %lease.address,
                prefix = lease.prefix_len,
                gateway = ?lease.gateway,
                mtu = ?lease.mtu,
                "network interface"
            ),
            None => warn!(interface = interface.name, "network interface without a lease"),
        }
    }
    info!(nameservers = ?network.nameservers, "DNS configured");

    let metadata = match platform {
        Some(platform) => platform.fetch().await.unwrap_or_else(|e| {
            error!(%platform, "fetching metadata failed: {e:#}");
            Metadata::default()
        }),
        None => Metadata::default(),
    };
    let settings = match &metadata.user_data {
        Some(raw) => match UserData::parse(raw) {
            Ok(user_data) => user_data.settings,
            Err(e) => {
                error!("ignoring invalid user-data: {e}");
                Settings::default()
            }
        },
        None => {
            info!("no user-data");
            Settings::default()
        }
    };

    if settings.dns != DnsSettings::default() {
        net::set_dns_override(settings.dns.clone())?;
    }
    let instance_id = metadata.instance_id.clone();
    let hostname = settings
        .network
        .hostname
        .clone()
        .or_else(|| metadata.hostname.clone())
        .or_else(|| network.dhcp_hostname.clone())
        .unwrap_or_else(|| Hostname::from_instance_id(instance_id.as_deref()));
    set_hostname(&hostname)?;
    info!(%hostname, instance_id = instance_id.as_deref().unwrap_or("none"), "identity configured");

    // In the background: the clock is already close (the hypervisor's), dust-ntp corrects it.
    let time_servers = Servers::choose(&settings.ntp, &network.ntp_servers);
    let ntp = Ntp::start(reaper.clone(), &time_servers)
        .inspect_err(|e| error!("cannot start time synchronization: {e:#}"))
        .ok();

    let kubelet = match &settings.kubernetes {
        KubernetesSettings::Enabled(config) if kubelet::installed() => Some(config),
        KubernetesSettings::Enabled(_) => {
            error!("settings.kubernetes is enabled, but this image has no kubelet");
            None
        }
        KubernetesSettings::Disabled => None,
    };
    if kubelet.is_some() {
        sysctl::apply_kubernetes_defaults();
    }
    sysctl::apply(&settings.kernel.sysctl);
    kmod::load(&settings.kernel.modules);

    let storage = storage::mount_state(&reaper, settings.hardened.storage.encryption).await?;
    for dir in ["/var/lib/containerd", "/var/lib/dust", workloads::LOG_DIR] {
        std::fs::create_dir_all(dir)?;
    }
    let kubelet_args = kubelet.and_then(|config| {
        kubelet::prepare(config, &hostname)
            .inspect_err(|e| error!("cannot prepare kubelet, it will not run: {e:#}"))
            .ok()
    });

    let containerd = containerd::start(reaper.clone(), &settings.container_registry);

    let tpm = match Tpm::open(Path::new(Tpm::DEVICE)) {
        Ok(Some(tpm)) => {
            info!("TPM available for attestation");
            Some(Arc::new(Mutex::new(tpm)))
        }
        Ok(None) => {
            info!("no TPM: attestation unavailable");
            None
        }
        Err(e) => {
            warn!("cannot open the TPM: {e}");
            None
        }
    };

    let machine = Arc::new(Machine {
        info: MachineInfo {
            os_name: "hardened",
            os_version,
            kernel,
            platform,
            instance_id,
            hostname,
            boot_id: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
                .ok()
                .and_then(|id| id.trim().parse().ok()),
            booted_at,
        },
        settings: settings.clone(),
        storage,
        time_servers,
        logs,
        workloads: OnceLock::new(),
        tpm,
        power: power_tx,
    });
    let control_machine = machine.clone();
    tokio::spawn(async move {
        if let Err(e) = control::serve(control_machine, Path::new(dust_proto::CONTROL_SOCKET)).await {
            error!("control API stopped: {e:#}");
        }
    });
    let api = match &settings.hardened.api {
        ApiSettings::Enabled(api) => Api::start(reaper.clone(), api)
            .inspect_err(|e| error!("cannot start the API: {e:#}"))
            .ok(),
        ApiSettings::Disabled => None,
    };
    let pods = match kubelet_args {
        Some(args) => Pods::Kubelet(tokio::spawn(start_kubelet(reaper.clone(), args))),
        None => Pods::Workloads(tokio::spawn(start_workloads(machine.clone()))),
    };

    let request = power_rx.recv().await.unwrap_or(PowerRequest::PowerOff);
    info!(?request, "shutting down");
    if let Some(api) = api {
        api.stop().await;
    }
    // A start still in progress is abandoned first, then whatever it started is stopped.
    match pods {
        Pods::Workloads(starting) => {
            starting.abort();
            let _ = starting.await;
            if let Some(workloads) = machine.workloads.get() {
                workloads.shutdown(SHUTDOWN_GRACE).await;
            }
        }
        Pods::Kubelet(starting) => {
            starting.abort();
            if let Ok(kubelet) = starting.await {
                kubelet.stop(KUBELET_GRACE).await;
                if let Err(e) = workloads::stop_all_pods(Path::new(containerd::SOCKET), SHUTDOWN_GRACE).await {
                    warn!("cannot stop kubelet's pods: {e:#}");
                }
            }
        }
    }
    containerd.stop(Duration::from_secs(10)).await;
    if let Some(ntp) = ntp {
        ntp.stop().await;
    }
    drop(machine);
    Ok(request)
}

/// Connects to containerd, retrying until it answers, then starts the user-data workloads and
/// the API-managed ones. The control API and dust-api already run, so a containerd that never
/// comes up can be diagnosed remotely (its log tail is copied to dust-init's).
async fn start_workloads(machine: Arc<Machine>) {
    let workloads = until_containerd_answers("workloads unavailable", || {
        Manager::connect(
            Path::new(containerd::SOCKET),
            Path::new("/var/lib/dust"),
            Path::new(workloads::LOG_DIR),
            Path::new(workloads::BUNDLED_IMAGES),
            Duration::from_secs(60),
        )
    })
    .await;
    let workloads = machine.workloads.get_or_init(|| workloads);

    for (name, container) in machine.settings.hardened.containers.iter().filter(|(_, c)| c.enabled) {
        if let Err(e) = workloads
            .apply(name, container.workload.clone(), Source::UserData)
            .await
        {
            error!(workload = %name, "cannot start workload: {e:#}");
        }
    }
    if let Err(e) = workloads.load_persisted().await {
        error!("cannot start API-managed workloads: {e:#}");
    }
    info!("boot complete");
}

/// Imports the bundled images (the pod sandbox's) once containerd answers, then starts kubelet.
/// dust-init's own workloads stay unavailable.
async fn start_kubelet(reaper: Reaper, args: Vec<String>) -> service::Service {
    until_containerd_answers("kubelet not started", || {
        workloads::import_bundled(
            Path::new(containerd::SOCKET),
            Path::new(workloads::BUNDLED_IMAGES),
            Duration::from_secs(60),
        )
    })
    .await;
    let kubelet = kubelet::start(reaper, args);
    info!("boot complete");
    kubelet
}

/// Calls `connect` until it succeeds, every [`CONNECT_RETRY`]; containerd's log tail is copied
/// to dust-init's after the first failure.
async fn until_containerd_answers<T, F>(consequence: &str, mut connect: impl FnMut() -> F) -> T
where
    F: Future<Output = anyhow::Result<T>>,
{
    let mut failures = 0u32;
    loop {
        match connect().await {
            Ok(connected) => return connected,
            Err(e) => {
                error!("cannot connect to containerd, {consequence}: {e:#}");
                if failures == 0 {
                    containerd::log_tail(40);
                }
                failures += 1;
                tokio::time::sleep(CONNECT_RETRY).await;
            }
        }
    }
}

fn set_hostname(hostname: &Hostname) -> anyhow::Result<()> {
    rustix::system::sethostname(hostname.as_str().as_bytes())?;
    std::fs::write(Path::new(net::RUNTIME_DIR).join("hostname"), format!("{hostname}\n"))?;
    net::write_hosts(hostname)?;
    Ok(())
}

fn os_release_field(key: &str) -> Option<String> {
    let text = std::fs::read_to_string("/usr/lib/os-release").ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix(key)?.strip_prefix('='))
        .map(|v| v.trim_matches('"').to_owned())
}

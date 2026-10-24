//! Machine inventory, logs and power management.

use std::io::{self, Write};

use dust_proto::v1::LogsRequest;
use dust_proto::v1::machine_client::MachineClient;
use tonic::transport::Channel;

use crate::client::{CallExt, CallFailed};

pub async fn version(channel: Channel) -> anyhow::Result<()> {
    let v = MachineClient::new(channel).version(()).await.into_result()?;
    let booted_at = v.booted_at.map(|t| t.to_string()).unwrap_or_default();
    let mut out = io::stdout().lock();
    writeln!(out, "Client:     hctl {}", env!("CARGO_PKG_VERSION"))?;
    for (label, value) in [
        ("OS:", format!("{} {}", v.os_name, v.os_version)),
        ("Kernel:", v.kernel),
        ("Platform:", v.platform),
        ("Instance:", v.instance_id),
        ("Hostname:", v.hostname),
        ("Boot ID:", v.boot_id),
        ("Booted at:", booted_at),
    ] {
        writeln!(out, "{label:<11} {value}")?;
    }
    Ok(())
}

pub async fn logs(channel: Channel, follow: bool, tail: u32) -> anyhow::Result<()> {
    let mut entries = MachineClient::new(channel)
        .logs(LogsRequest { follow, tail })
        .await
        .into_result()?;
    let mut out = io::stdout().lock();
    while let Some(entry) = entries.message().await.map_err(CallFailed)? {
        let time = entry.time.map(|t| t.to_string()).unwrap_or_else(|| "-".into());
        writeln!(out, "{time} {:>5} {}: {}", entry.level, entry.target, entry.message)?;
    }
    Ok(())
}

pub async fn settings(channel: Channel) -> anyhow::Result<()> {
    let settings = MachineClient::new(channel).get_settings(()).await.into_result()?;
    let mut out = io::stdout().lock();
    out.write_all(settings.toml.as_bytes())?;
    out.flush()?;
    Ok(())
}

pub async fn reboot(channel: Channel) -> anyhow::Result<()> {
    MachineClient::new(channel).reboot(()).await.into_result()?;
    eprintln!("rebooting");
    Ok(())
}

pub async fn shutdown(channel: Channel) -> anyhow::Result<()> {
    MachineClient::new(channel).shutdown(()).await.into_result()?;
    eprintln!("shutting down");
    Ok(())
}

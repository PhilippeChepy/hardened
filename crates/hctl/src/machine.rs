//! Machine inventory, logs and power management.

use std::io::{self, Write};

use dust_proto::v1::machine_client::MachineClient;
use dust_proto::v1::storage_response::State;
use dust_proto::v1::{LogsRequest, StorageResponse};
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

pub async fn storage(channel: Channel) -> anyhow::Result<()> {
    let storage = MachineClient::new(channel).storage(()).await.into_result()?;
    let mut out = io::stdout().lock();
    for line in storage_lines(&storage) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// `hctl storage`'s output.
fn storage_lines(storage: &StorageResponse) -> Vec<String> {
    let state = match storage.state() {
        State::Plain => "state partition, unencrypted",
        State::EncryptedUnlocked => "encrypted state partition, unlocked with the TPM",
        State::EncryptedFormatted => "encrypted state partition, formatted on this boot",
        State::Tmpfs => "tmpfs: nothing persists",
        State::Unspecified => "unknown",
    };
    let mut lines = vec![format!("{:<11} {state}", "State:")];
    for (label, value) in [
        ("Reason:", storage.reason.clone()),
        ("Partition:", storage.partition.clone()),
        ("Device:", storage.device.clone()),
    ] {
        if !value.is_empty() {
            lines.push(format!("{label:<11} {value}"));
        }
    }
    if storage.size_bytes > 0 {
        const GIB: f64 = (1u64 << 30) as f64;
        lines.push(format!(
            "{:<11} {:.1} GiB, {:.1} GiB available",
            "Size:",
            storage.size_bytes as f64 / GIB,
            storage.available_bytes as f64 / GIB
        ));
    }
    lines
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shows_storage() {
        let storage = StorageResponse {
            state: State::EncryptedFormatted.into(),
            reason: "it was not encrypted (first boot with encryption)".into(),
            partition: "/dev/vda4".into(),
            device: "/dev/mapper/state".into(),
            size_bytes: 4 << 30,
            available_bytes: 3 << 30,
        };
        assert_eq!(
            storage_lines(&storage),
            [
                "State:      encrypted state partition, formatted on this boot",
                "Reason:     it was not encrypted (first boot with encryption)",
                "Partition:  /dev/vda4",
                "Device:     /dev/mapper/state",
                "Size:       4.0 GiB, 3.0 GiB available",
            ]
        );
        let tmpfs = StorageResponse {
            state: State::Tmpfs.into(),
            reason: "no state partition".into(),
            ..StorageResponse::default()
        };
        assert_eq!(
            storage_lines(&tmpfs),
            ["State:      tmpfs: nothing persists", "Reason:     no state partition"]
        );
    }
}

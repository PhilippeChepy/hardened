//! Machine inventory, logs and power management.

use std::io::{self, Write};

use dust_proto::v1::machine_client::MachineClient;
use dust_proto::v1::storage_response::State;
use dust_proto::v1::time_response::Origin;
use dust_proto::v1::{LogsRequest, StorageResponse, TimeResponse};
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

pub async fn time(channel: Channel) -> anyhow::Result<()> {
    let time = MachineClient::new(channel).time(()).await.into_result()?;
    let mut out = io::stdout().lock();
    for line in time_lines(&time) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// `hctl time`'s output.
fn time_lines(time: &TimeResponse) -> Vec<String> {
    let ms = |nanos: i64| nanos as f64 / 1e6;
    let origin = match time.origin() {
        Origin::Settings => "settings.ntp.time-servers",
        Origin::Dhcp => "DHCP",
        Origin::Default => "default",
        Origin::Unspecified => "unknown",
    };
    let mut lines = vec![
        format!("Synchronized:  {}", if time.synchronized { "yes" } else { "no" }),
        format!("Servers:       {} ({origin})", time.servers.join(", ")),
    ];
    if let Some(corrected_at) = &time.corrected_at {
        let how = if time.stepped { "stepped" } else { "slewed" };
        lines.extend([
            format!("Corrected at:  {corrected_at}"),
            format!(
                "Server:        {} ({}), stratum {}, reference {}",
                time.server, time.address, time.stratum, time.reference
            ),
            format!(
                "Offset:        {:+.3} ms ({how}), round trip {:.3} ms",
                ms(time.offset_ns),
                ms(time.delay_ns)
            ),
        ]);
    }
    lines.push(format!(
        "Error:         {:.3} ms estimated, {:.3} ms at most",
        time.estimated_error_us as f64 / 1e3,
        time.max_error_us as f64 / 1e3
    ));
    lines.push(format!("Frequency:     {:+.3} ppm", time.frequency_ppm));
    if time.poll_interval_seconds > 0 {
        lines.push(format!("Poll interval: {} s", time.poll_interval_seconds));
    }
    if !time.error.is_empty() {
        lines.push(format!("Last error:    {}", time.error));
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

    #[test]
    fn shows_time() {
        let time = TimeResponse {
            synchronized: true,
            estimated_error_us: 6_100,
            max_error_us: 23_000,
            frequency_ppm: -12.5,
            servers: vec!["pool.ntp.org".into()],
            origin: Origin::Default.into(),
            server: "pool.ntp.org".into(),
            address: "192.0.2.1:123".into(),
            stratum: 2,
            reference: "192.0.2.10".into(),
            offset_ns: -1_465_000,
            delay_ns: 12_300_000,
            stepped: false,
            corrected_at: Some(
                (std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_767_225_600)).into(),
            ),
            poll_interval_seconds: 64,
            error: String::new(),
        };
        assert_eq!(
            time_lines(&time),
            [
                "Synchronized:  yes",
                "Servers:       pool.ntp.org (default)",
                "Corrected at:  2026-01-01T00:00:00Z",
                "Server:        pool.ntp.org (192.0.2.1:123), stratum 2, reference 192.0.2.10",
                "Offset:        -1.465 ms (slewed), round trip 12.300 ms",
                "Error:         6.100 ms estimated, 23.000 ms at most",
                "Frequency:     -12.500 ppm",
                "Poll interval: 64 s",
            ]
        );
        let never = TimeResponse {
            servers: vec!["10.0.0.4".into()],
            origin: Origin::Dhcp.into(),
            error: "10.0.0.4 (10.0.0.4:123): no reply within 2s".into(),
            ..TimeResponse::default()
        };
        assert_eq!(
            time_lines(&never),
            [
                "Synchronized:  no",
                "Servers:       10.0.0.4 (DHCP)",
                "Error:         0.000 ms estimated, 0.000 ms at most",
                "Frequency:     +0.000 ppm",
                "Last error:    10.0.0.4 (10.0.0.4:123): no reply within 2s",
            ]
        );
    }
}

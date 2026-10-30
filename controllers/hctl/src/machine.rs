//! Machine inventory, logs and power management.

use std::io::{self, Write};

use machine_controller::machine::LogsRequest;
use machine_controller::machine::machine_client::MachineClient;
use storage_controller::storage;
use storage_controller::storage::state::Backing;
use time_controller::time;
use time_controller::time::Origin;
use tonic::transport::Channel;

use crate::client::{CallExt, CallFailed};
use crate::settings_toml;

/// `hctl version`.
pub async fn version(channel: Channel) -> anyhow::Result<()> {
    let version = MachineClient::new(channel)
        .version(())
        .await
        .into_result()?;
    let booted_at = version
        .booted_at
        .map(|time| time.to_string())
        .unwrap_or_default();
    let mut out = io::stdout().lock();
    writeln!(out, "Client:     hctl {}", env!("CARGO_PKG_VERSION"))?;
    for (label, value) in [
        ("OS:", format!("{} {}", version.os_name, version.os_version)),
        ("Kernel:", version.kernel),
        ("Platform:", version.platform),
        ("Instance:", version.instance_id),
        ("Hostname:", version.hostname),
        ("Boot ID:", version.boot_id),
        ("Booted at:", booted_at),
    ] {
        writeln!(out, "{label:<11} {value}")?;
    }
    Ok(())
}

/// `hctl logs`.
pub async fn logs(channel: Channel, follow: bool, tail: u32) -> anyhow::Result<()> {
    let mut entries = MachineClient::new(channel)
        .logs(LogsRequest { follow, tail })
        .await
        .into_result()?;
    let mut out = io::stdout().lock();
    while let Some(entry) = entries.message().await.map_err(CallFailed)? {
        let time = entry
            .time
            .map_or_else(|| "-".to_owned(), |time| time.to_string());
        writeln!(
            out,
            "{time} {:>5} {}: {}",
            entry.level, entry.target, entry.message
        )?;
    }
    Ok(())
}

/// `hctl settings`.
pub async fn settings(channel: Channel) -> anyhow::Result<()> {
    let settings = MachineClient::new(channel)
        .get_settings(())
        .await
        .into_result()?;
    write!(io::stdout().lock(), "{}", settings_toml::table(&settings)?)?;
    Ok(())
}

/// `hctl storage`.
pub async fn storage(channel: Channel) -> anyhow::Result<()> {
    let storage = MachineClient::new(channel)
        .storage(())
        .await
        .into_result()?;
    let mut out = io::stdout().lock();
    for line in storage_lines(&storage) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// `hctl storage`'s output.
#[must_use]
fn storage_lines(storage: &storage::State) -> Vec<String> {
    let none = "";
    let (state, reason, partition) = match &storage.backing {
        Some(Backing::Plain(plain)) => ("state partition, unencrypted", none, &*plain.partition),
        Some(Backing::Unlocked(unlocked)) => (
            "encrypted state partition, unlocked with the TPM",
            none,
            &*unlocked.partition,
        ),
        Some(Backing::Formatted(formatted)) => (
            "encrypted state partition, formatted on this boot",
            &*formatted.reason,
            &*formatted.partition,
        ),
        Some(Backing::Tmpfs(tmpfs)) => ("tmpfs: nothing persists", &*tmpfs.reason, none),
        None => ("unknown", none, none),
    };
    let mut lines = vec![format!("{:<11} {state}", "State:")];
    for (label, value) in [("Reason:", reason), ("Partition:", partition)] {
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

/// `hctl time`.
pub async fn time(channel: Channel) -> anyhow::Result<()> {
    let time = MachineClient::new(channel).time(()).await.into_result()?;
    let mut out = io::stdout().lock();
    for line in time_lines(&time) {
        writeln!(out, "{line}")?;
    }
    Ok(())
}

/// `hctl time`'s output.
#[must_use]
fn time_lines(time: &time::Status) -> Vec<String> {
    let milliseconds = |nanos: i64| nanos as f64 / 1e6;
    let clock = time.clock.unwrap_or_default();
    let origin = match time.origin() {
        Origin::Settings => "settings.ntp.time-servers",
        Origin::Dhcp => "DHCP",
        Origin::Default => "default",
        Origin::Unspecified => "unknown",
    };
    let mut lines = vec![
        format!(
            "Synchronized:  {}",
            if clock.synchronized { "yes" } else { "no" }
        ),
        format!("Servers:       {} ({origin})", time.servers.join(", ")),
    ];
    if let Some(correction) = &time.last_correction {
        let how = if correction.stepped {
            "stepped"
        } else {
            "slewed"
        };
        let corrected_at = correction
            .corrected_at
            .map_or_else(|| "-".to_owned(), |time| time.to_string());
        lines.extend([
            format!("Corrected at:  {corrected_at}"),
            format!(
                "Server:        {} ({}), stratum {}, reference {}",
                correction.server, correction.address, correction.stratum, correction.reference
            ),
            format!(
                "Offset:        {:+.3} ms ({how}), round trip {:.3} ms",
                milliseconds(correction.offset_ns),
                milliseconds(correction.delay_ns)
            ),
        ]);
    }
    lines.push(format!(
        "Error:         {:.3} ms estimated, {:.3} ms at most",
        clock.estimated_error_us as f64 / 1e3,
        clock.max_error_us as f64 / 1e3
    ));
    lines.push(format!("Frequency:     {:+.3} ppm", clock.frequency_ppm));
    if time.poll_interval_seconds > 0 {
        lines.push(format!("Poll interval: {} s", time.poll_interval_seconds));
    }
    if let Some(error) = &time.error {
        lines.push(format!("Last error:    {error}"));
    }
    lines
}

/// `hctl reboot`.
pub async fn reboot(channel: Channel) -> anyhow::Result<()> {
    MachineClient::new(channel).reboot(()).await.into_result()?;
    eprintln!("rebooting");
    Ok(())
}

/// `hctl shutdown`.
pub async fn shutdown(channel: Channel) -> anyhow::Result<()> {
    MachineClient::new(channel)
        .shutdown(())
        .await
        .into_result()?;
    eprintln!("shutting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, SystemTime};

    use super::*;

    #[test]
    fn shows_storage() {
        let storage = storage::State {
            backing: Some(Backing::Formatted(storage::state::Formatted {
                partition: "/dev/vda4".into(),
                reason: "it was not encrypted (first boot with encryption)".into(),
            })),
            size_bytes: 4 << 30,
            available_bytes: 3 << 30,
        };
        assert_eq!(
            storage_lines(&storage),
            [
                "State:      encrypted state partition, formatted on this boot",
                "Reason:     it was not encrypted (first boot with encryption)",
                "Partition:  /dev/vda4",
                "Size:       4.0 GiB, 3.0 GiB available",
            ]
        );
        let tmpfs = storage::State {
            backing: Some(Backing::Tmpfs(storage::state::Tmpfs {
                reason: "no state partition".into(),
            })),
            ..storage::State::default()
        };
        assert_eq!(
            storage_lines(&tmpfs),
            [
                "State:      tmpfs: nothing persists",
                "Reason:     no state partition"
            ]
        );
    }

    #[test]
    fn shows_time() {
        let time = time::Status {
            clock: Some(time::Clock {
                synchronized: true,
                estimated_error_us: 6_100,
                max_error_us: 23_000,
                frequency_ppm: -12.5,
            }),
            servers: vec!["pool.ntp.org".into()],
            origin: Origin::Default.into(),
            last_correction: Some(time::Correction {
                server: "pool.ntp.org".into(),
                address: "192.0.2.1:123".into(),
                stratum: 2,
                reference: "192.0.2.10".into(),
                offset_ns: -1_465_000,
                delay_ns: 12_300_000,
                stepped: false,
                corrected_at: Some(
                    (SystemTime::UNIX_EPOCH + Duration::from_secs(1_767_225_600)).into(),
                ),
            }),
            error: None,
            poll_interval_seconds: 64,
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
        let never = time::Status {
            servers: vec!["10.0.0.4".into()],
            origin: Origin::Dhcp.into(),
            error: Some("10.0.0.4 (10.0.0.4:123): no reply within 2s".into()),
            ..time::Status::default()
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

//! Local qemu: user-data is passed with
//! `-fw_cfg name=opt/hardened/user-data,file=user-data.toml` and read from sysfs.

use std::fs;
use std::io::ErrorKind;

use crate::metadata::Metadata;

/// Where the kernel exposes the user-data fw_cfg entry.
pub const FW_CFG_USER_DATA: &str = "/sys/firmware/qemu_fw_cfg/by_name/opt/hardened/user-data/raw";

/// Reads the user-data qemu was given, and the SMBIOS product UUID as the instance ID.
pub async fn fetch() -> anyhow::Result<Metadata> {
    let user_data = match tokio::fs::read(FW_CFG_USER_DATA).await {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(anyhow::Error::new(e).context(FW_CFG_USER_DATA)),
    };
    let instance_id = fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .ok()
        .map(|uuid| uuid.trim().to_owned())
        .filter(|uuid| !uuid.is_empty());
    Ok(Metadata {
        instance_id,
        user_data,
        ..Metadata::default()
    })
}

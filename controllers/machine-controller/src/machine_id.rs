//! `/etc/machine-id`, which cAdvisor and the node's `machineID` read: derived from the instance
//! ID, so it lasts as long as the instance without any state (a formatted `/var` keeps it), and
//! does not disclose the ID itself. Without an instance ID, it is random, for this boot.

use std::fmt;
use std::fmt::Display;
use std::fmt::Formatter;
use std::path::Path;

use anyhow::Context;
use controllers_helpers::atomic_file;
use rustix::rand::GetRandomFlags;
use sha2::Digest as _;
use sha2::Sha256;

/// Where `/etc/machine-id` links to.
const PATH: &str = "/run/hardened/machine-id";
/// Hashed before the instance ID: the machine ID is hardened's own.
const DOMAIN: &[u8] = b"hardened machine-id\0";

/// 128 bits, shaped as a version 4 UUID, as systemd's are.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MachineId([u8; 16]);

impl MachineId {
    /// The ID of the instance `instance_id`, or a random one without.
    ///
    /// # Errors
    ///
    /// When there is no instance ID and the kernel gives no random bytes.
    pub fn new(instance_id: Option<&str>) -> anyhow::Result<Self> {
        let mut bytes = [0; 16];
        match instance_id {
            Some(id) => {
                let digest = Sha256::new()
                    .chain_update(DOMAIN)
                    .chain_update(id)
                    .finalize();
                for (byte, hashed) in bytes.iter_mut().zip(digest.iter()) {
                    *byte = *hashed;
                }
            }
            None => {
                rustix::rand::getrandom(&mut bytes, GetRandomFlags::empty())
                    .context("random bytes")?;
            }
        }
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        Ok(Self(bytes))
    }

    /// Writes it where `/etc/machine-id` links to.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn write(self) -> anyhow::Result<()> {
        atomic_file::write(Path::new(PATH), format!("{self}\n").as_bytes(), 0o444).context(PATH)
    }
}

/// 32 lowercase hexadecimal digits, as in `/etc/machine-id`.
impl Display for MachineId {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stable_per_instance_and_shaped_as_a_uuid() {
        let id = MachineId::new(Some("1f2e3d4c-0000-4000-8000-000000000001")).unwrap();
        assert_eq!(
            id,
            MachineId::new(Some("1f2e3d4c-0000-4000-8000-000000000001")).unwrap()
        );
        assert_ne!(id, MachineId::new(Some("another instance")).unwrap());
        let text = id.to_string();
        assert_eq!(text.len(), 32);
        assert!(
            text.bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
        );
        assert_eq!(&text[12..13], "4", "version 4");
        assert!("89ab".contains(&text[16..17]), "variant 1");
        assert!(
            !text.contains("1f2e3d4c"),
            "the instance ID is not disclosed"
        );

        assert_ne!(MachineId::new(None).unwrap(), MachineId::new(None).unwrap());
    }
}

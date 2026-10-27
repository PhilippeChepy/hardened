//! Remote attestation evidence from the (v)TPM, and the TPM client sealing the state partition's
//! key.
//!
//! dust-init talks to the TPM resource manager (`/dev/tpmrm0`) with hand-marshalled TPM 2.0 commands:
//! no TSS library, no daemon. Evidence is the PCR banks, the TCG event log written by the
//! firmware and systemd-stub (the UKI measures its sections into PCR 11), and quotes signed by an
//! attestation key derived deterministically under the endorsement hierarchy.

mod tpm;

#[cfg(test)]
pub use tpm::ResponseCode;
pub use tpm::{HashAlg, Sealed, Tpm, TpmError};

/// Firmware + systemd-stub event log, exported by the kernel through securityfs.
pub const EVENT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";

/// Reads the raw TCG event log.
pub fn event_log() -> std::io::Result<Vec<u8>> {
    std::fs::read(EVENT_LOG)
}

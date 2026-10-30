//! How commands reach the TPM: its character device, or a test double.

use std::fs::File;
use std::io::{self, ErrorKind};

/// The kernel's TPM_BUFSIZE: no command or response is larger.
const MAX_RESPONSE_LEN: usize = 4096;

/// Sends a marshalled command to a TPM and returns its marshalled response.
pub trait Transport {
    /// Sends `command` and waits for the whole response.
    fn transact(&mut self, command: &[u8]) -> io::Result<Vec<u8>>;
}

/// A TPM character device (`/dev/tpmrm0`).
#[derive(Debug)]
pub(crate) struct Device(pub(crate) File);

impl Transport for Device {
    fn transact(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
        use std::io::{Read as _, Write as _};

        // The driver requires the command in a single write. No EINTR to retry: the only signal
        // handled, SIGTERM, restarts system calls.
        let written = self.0.write(command)?;
        if written != command.len() {
            return Err(io::Error::new(
                ErrorKind::WriteZero,
                "partial write of a tpm command",
            ));
        }
        let mut response = vec![0; MAX_RESPONSE_LEN];
        let len = self.0.read(&mut response)?;
        response.truncate(len);
        Ok(response)
    }
}

/// A TPM whose every answer is an error: enough to check what happens before it.
#[cfg(test)]
pub struct Unplugged;

#[cfg(test)]
impl Transport for Unplugged {
    fn transact(&mut self, _: &[u8]) -> io::Result<Vec<u8>> {
        Err(io::Error::other("unplugged"))
    }
}

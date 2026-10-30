//! Pseudo-terminals, their master side asynchronous.

use std::io;
use std::os::fd::OwnedFd;

use rustix::fs::Mode;
use rustix::fs::OFlags;
use rustix::io::Errno;
use rustix::pty::OpenptFlags;
use rustix::termios::Winsize;
use tokio::io::unix::AsyncFd;
use workload_console::TerminalSize;

/// The master side of a pseudo-terminal.
pub struct Pty {
    master: AsyncFd<OwnedFd>,
}

impl Pty {
    /// A pseudo-terminal of `size`, and its slave side. Within a tokio runtime.
    pub fn open(size: TerminalSize) -> io::Result<(Self, OwnedFd)> {
        let master = rustix::pty::openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY)?;
        rustix::pty::grantpt(&master)?;
        rustix::pty::unlockpt(&master)?;
        let name = rustix::pty::ptsname(&master, Vec::new())?;
        let slave = rustix::fs::open(
            name.as_c_str(),
            OFlags::RDWR | OFlags::NOCTTY | OFlags::CLOEXEC,
            Mode::empty(),
        )?;
        rustix::termios::tcsetwinsize(&master, winsize(size))?;
        rustix::io::ioctl_fionbio(&master, true)?;
        // SAFETY: the `OwnedFd` keeps it open for as long as the `AsyncFd` owns it.
        let master = unsafe { AsyncFd::register(master) }?;
        Ok((Self { master }, slave))
    }

    /// 0 once no process holds the slave side.
    pub async fn read(&self, buffer: &mut [u8]) -> io::Result<usize> {
        loop {
            let mut ready = self.master.readable().await?;
            match ready.try_io(|master| Ok(rustix::io::read(master.get_ref(), &mut *buffer)?)) {
                Err(_would_block) => continue,
                // Linux's end of file on a master whose slave side is closed.
                Ok(Err(error)) if error.raw_os_error() == Some(Errno::IO.raw_os_error()) => {
                    return Ok(0);
                }
                Ok(result) => return result,
            }
        }
    }

    pub async fn write_all(&self, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let mut ready = self.master.writable().await?;
            match ready.try_io(|master| Ok(rustix::io::write(master.get_ref(), data)?)) {
                Err(_would_block) => continue,
                Ok(written) => data = &data[written?..],
            }
        }
        Ok(())
    }

    pub fn resize(&self, size: TerminalSize) -> io::Result<()> {
        Ok(rustix::termios::tcsetwinsize(
            self.master.get_ref(),
            winsize(size),
        )?)
    }
}

#[must_use]
fn winsize(size: TerminalSize) -> Winsize {
    Winsize {
        ws_row: size.rows,
        ws_col: size.columns,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}

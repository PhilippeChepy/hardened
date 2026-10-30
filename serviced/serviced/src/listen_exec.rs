//! Passing a service's sockets to its `exec`, as systemd does and `libserviced::activation`
//! reads them: fds from 3 in the order of the service file, `LISTEN_FDS`, `LISTEN_FDNAMES`
//! (colon-separated), `LISTEN_PID` (the process's own pid), and per socket
//! `SERVICED_ALLOW_<NAME>` (comma-separated service names).
//!
//! `LISTEN_PID` is only known once forked, where nothing may be allocated: the environment is
//! prepared beforehand with room for any pid, which the child writes in before its own `execve`
//! ([`ListenExec`]). The fds are put in place by [`PassedFds`], before the sandbox's seccomp
//! filter forbids `dup2`.

use std::ffi::{CString, c_char};
use std::io;
use std::os::fd::{AsRawFd as _, OwnedFd, RawFd};
use std::ptr;
use std::sync::Arc;

use anyhow::Context as _;
use libserviced::activation::FIRST_FD;
use libserviced::activation::LISTEN_FDNAMES;
use libserviced::activation::LISTEN_FDS;
use libserviced::activation::LISTEN_PID;

use crate::service_sockets::Listener;

/// Digits of the largest pid (`u32::MAX`), and the terminating NUL.
const PID_ROOM: usize = 11;

/// The variables describing `listeners`, but `LISTEN_PID`.
#[must_use]
pub fn environment(listeners: &[Listener]) -> Vec<(String, String)> {
    let names: Vec<&str> = listeners
        .iter()
        .map(|listener| listener.socket.name.as_str())
        .collect();
    let mut variables = vec![
        (LISTEN_FDS.to_owned(), listeners.len().to_string()),
        (LISTEN_FDNAMES.to_owned(), names.join(":")),
    ];
    for listener in listeners {
        let allow: Vec<&str> = listener
            .socket
            .allow
            .iter()
            .map(|service| service.as_str())
            .collect();
        variables.push((listener.socket.name.allow_variable(), allow.join(",")));
    }
    variables
}

/// The sockets to put at fds 3 and up in the child.
pub struct PassedFds {
    sources: Vec<Arc<OwnedFd>>,
    /// Copies above the targets, so that placing one never closes another source.
    copies: Box<[RawFd]>,
}

impl PassedFds {
    /// The fds of `listeners`, kept open by this until the `exec`.
    #[must_use]
    pub fn new(listeners: &[Listener]) -> Self {
        Self {
            sources: listeners
                .iter()
                .map(|listener| listener.fd.clone())
                .collect(),
            copies: vec![-1; listeners.len()].into_boxed_slice(),
        }
    }

    /// Puts the sockets at fds 3 and up, inherited by the `exec`. Runs in the child between
    /// `fork` and `exec`: system calls only.
    pub fn place(&mut self) -> io::Result<()> {
        let count = RawFd::try_from(self.sources.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let above = FIRST_FD + count;
        for (copy, source) in self.copies.iter_mut().zip(&self.sources) {
            // SAFETY: fcntl(2) takes no pointer; `source` is an open fd, owned by the parent's
            // `Arc` this child inherited.
            let fd = unsafe { libc::fcntl(source.as_raw_fd(), libc::F_DUPFD_CLOEXEC, above) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            *copy = fd;
        }
        for (target, &copy) in (FIRST_FD..).zip(self.copies.iter()) {
            // SAFETY: dup2(2) takes no pointer; `copy` is open, and `target` is free or one of
            // the sources, copied above. The new fd is not close-on-exec: it is for the exec;
            // the copies are, and close with it.
            if unsafe { libc::dup2(copy, target) } < 0 {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }
}

/// The `execve` of a program, its environment with `LISTEN_PID` set to the child's pid.
pub struct ListenExec {
    program: CString,
    argv: Vec<CString>,
    /// `KEY=value` and a NUL, each.
    env: Vec<Vec<u8>>,
    /// The entry of `LISTEN_PID`, with room for any pid.
    pid_entry: usize,
    /// Filled in the child: pointers into `argv` and `env`, then a null pointer.
    argv_pointers: Box<[*const c_char]>,
    env_pointers: Box<[*const c_char]>,
}

// SAFETY: the pointer arrays are only written and read in the forked child, where they point
// into the buffers of the same value; elsewhere they are null and never dereferenced.
unsafe impl Send for ListenExec {}
// SAFETY: as for `Send`: no shared access dereferences the pointers.
unsafe impl Sync for ListenExec {}

impl ListenExec {
    /// The `execve` of `program` with `args`, and the environment `variables` plus `LISTEN_PID`.
    pub fn try_new<'a>(
        program: &str,
        args: &[String],
        variables: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> anyhow::Result<Self> {
        let program = CString::new(program).context("the program contains a NUL")?;
        let mut argv = vec![program.clone()];
        for arg in args {
            argv.push(CString::new(arg.as_str()).context("an argument contains a NUL")?);
        }
        let mut env = Vec::new();
        for (key, value) in variables {
            let entry =
                CString::new(format!("{key}={value}")).context("the environment contains a NUL")?;
            env.push(entry.into_bytes_with_nul());
        }
        let pid_entry = env.len();
        let mut entry = format!("{LISTEN_PID}=").into_bytes();
        entry.resize(entry.len() + PID_ROOM, 0);
        env.push(entry);
        Ok(Self {
            argv_pointers: vec![ptr::null(); argv.len() + 1].into_boxed_slice(),
            env_pointers: vec![ptr::null(); env.len() + 1].into_boxed_slice(),
            program,
            argv,
            env,
            pid_entry,
        })
    }

    /// Sets `LISTEN_PID` to this process and executes the program; returns only if that failed.
    /// Runs in the child between `fork` and `exec`: no allocation, no lock.
    #[must_use]
    pub fn exec(&mut self) -> io::Error {
        let pid = rustix::process::getpid()
            .as_raw_nonzero()
            .get()
            .unsigned_abs();
        write_pid(&mut self.env[self.pid_entry], LISTEN_PID.len() + 1, pid);
        for (pointer, arg) in self.argv_pointers.iter_mut().zip(&self.argv) {
            *pointer = arg.as_ptr();
        }
        for (pointer, entry) in self.env_pointers.iter_mut().zip(&self.env) {
            *pointer = entry.as_ptr().cast();
        }
        // SAFETY: the program is a NUL-terminated string; both arrays end with a null pointer
        // (their last element, never overwritten) and point into NUL-terminated buffers of
        // `self`, which outlive the call.
        unsafe {
            libc::execve(
                self.program.as_ptr(),
                self.argv_pointers.as_ptr(),
                self.env_pointers.as_ptr(),
            );
        }
        io::Error::last_os_error()
    }
}

/// Writes `pid` in decimal into `entry` from `start`, then a NUL: [`PID_ROOM`] bytes at most.
fn write_pid(entry: &mut [u8], start: usize, pid: u32) {
    let mut digits = [0u8; PID_ROOM - 1];
    let mut first = digits.len();
    let mut rest = pid;
    loop {
        first -= 1;
        digits[first] = b'0' + u8::try_from(rest % 10).unwrap_or_default();
        rest /= 10;
        if rest == 0 {
            break;
        }
    }
    let digits = &digits[first..];
    entry[start..start + digits.len()].copy_from_slice(digits);
    entry[start + digits.len()] = 0;
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::os::unix::net::UnixListener;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt as _;
    use std::path::Path;

    use libserviced::definition::Socket;

    use super::*;
    use crate::exit::Exit;

    fn listener(dir: &Path, text: &str) -> Listener {
        let socket: Socket = toml::from_str(text).unwrap();
        let fd = UnixListener::bind(dir.join(socket.name.as_str())).unwrap();
        Listener {
            socket,
            fd: Arc::new(OwnedFd::from(fd)),
        }
    }

    #[test]
    fn pids_fit_their_room() {
        let mut entry = *b"LISTEN_PID=\0\0\0\0\0\0\0\0\0\0\0";
        write_pid(&mut entry, 11, u32::MAX);
        assert_eq!(&entry, b"LISTEN_PID=4294967295\0");
        write_pid(&mut entry, 11, 7);
        assert!(entry.starts_with(b"LISTEN_PID=7\0"));
        write_pid(&mut entry, 11, 0);
        assert!(entry.starts_with(b"LISTEN_PID=0\0"));
    }

    #[test]
    fn environment_describes_the_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let listeners = [
            listener(
                dir.path(),
                "name = \"api\"\npath = \"/run/a/api.sock\"\n\
                 allow = [\"machine-apiproxy\", \"machine-controller\"]\n",
            ),
            listener(
                dir.path(),
                "name = \"machine-admin\"\npath = \"/run/a/b.sock\"\n",
            ),
        ];
        let variables = environment(&listeners);
        let variables: Vec<(&str, &str)> = variables
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        assert_eq!(
            variables,
            [
                ("LISTEN_FDS", "2"),
                ("LISTEN_FDNAMES", "api:machine-admin"),
                ("SERVICED_ALLOW_API", "machine-apiproxy,machine-controller"),
                ("SERVICED_ALLOW_MACHINE_ADMIN", ""),
            ]
        );
    }

    /// What the child sees, as libserviced reads it: the variables, and a socket at each fd.
    #[test]
    fn the_child_inherits_its_sockets() {
        let dir = tempfile::tempdir().unwrap();
        let listeners = [
            listener(
                dir.path(),
                "name = \"api\"\npath = \"/x\"\nallow = [\"web\"]\n",
            ),
            listener(dir.path(), "name = \"admin\"\npath = \"/y\"\n"),
        ];
        let mut variables = environment(&listeners);
        variables.push(("GREETING".to_owned(), "hello".to_owned()));
        // Shell builtins only: the environment has no PATH.
        let script = "echo \"$GREETING $LISTEN_PID $$ $LISTEN_FDS $LISTEN_FDNAMES \
                      $SERVICED_ALLOW_API.$SERVICED_ALLOW_ADMIN\"; \
                      test -S /proc/self/fd/3 && test -S /proc/self/fd/4 && echo sockets";
        let mut exec = ListenExec::try_new(
            "/bin/sh",
            &["-c".to_owned(), script.to_owned()],
            variables
                .iter()
                .map(|(key, value)| (key.as_str(), value.as_str())),
        )
        .unwrap();
        let mut fds = PassedFds::new(&listeners);
        let mut command = std::process::Command::new("/nonexistent/never-run");
        // SAFETY: both closures only make system calls on what was prepared.
        unsafe {
            command.pre_exec(move || fds.place());
            command.pre_exec(move || Err(exec.exec()));
        }
        // Through the tests' reaper, which collects every child of the process.
        let output = dir.path().join("output");
        command.stdout(File::create(&output).unwrap());
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let child = runtime
            .block_on(crate::process::test_reaper().spawn(&mut command))
            .unwrap();
        assert_eq!(runtime.block_on(child.wait()), Exit::Code(0));
        let stdout = fs::read_to_string(&output).unwrap();
        let lines: Vec<&str> = stdout.lines().collect();
        let fields: Vec<&str> = lines[0].split(' ').collect();
        assert_eq!(fields[0], "hello");
        assert_eq!(fields[1], fields[2], "LISTEN_PID is the child's pid");
        assert_eq!(fields[3..], ["2", "api:admin", "web."]);
        assert_eq!(lines[1..], ["sockets"], "at fds 3 and 4");

        // A client of the first socket reaches the listener the child had at fd 3.
        UnixStream::connect(dir.path().join("api")).unwrap();
    }

    #[test]
    fn failed_execs_are_reported() {
        let mut exec = ListenExec::try_new("/nonexistent/program", &[], []).unwrap();
        let mut command = std::process::Command::new("/bin/true");
        // SAFETY: the closure only makes system calls on what was prepared.
        unsafe {
            command.pre_exec(move || Err(exec.exec()));
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let Err(error) = runtime.block_on(crate::process::test_reaper().spawn(&mut command)) else {
            panic!("the exec failed");
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
    }
}

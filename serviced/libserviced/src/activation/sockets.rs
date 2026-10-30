use std::env;
use std::io;
use std::os::fd::BorrowedFd;
use std::os::fd::FromRawFd;
use std::os::fd::OwnedFd;
use std::os::fd::RawFd;
use std::os::unix::net::UnixListener;
use std::process;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use rustix::fs::FileType;
use rustix::io::FdFlags;

use crate::activation::ActivatedSocket;
use crate::definition::ServiceName;
use crate::definition::SocketName;

/// The first passed fd, after stdin, stdout and stderr.
pub const FIRST_FD: RawFd = 3;
/// The pid of the process the sockets are passed to: its children ignore them.
pub const LISTEN_PID: &str = "LISTEN_PID";
/// How many sockets are passed.
pub const LISTEN_FDS: &str = "LISTEN_FDS";
/// The passed sockets' names, colon-separated.
pub const LISTEN_FDNAMES: &str = "LISTEN_FDNAMES";

/// Set by the first [`Sockets::from_env`], so that the passed fds have one owner even though
/// their variables stay in the environment.
static TAKEN: AtomicBool = AtomicBool::new(false);

/// Why the passed sockets cannot be taken.
#[derive(Debug, thiserror::Error)]
pub enum ActivationError {
    /// A variable is not set: the process was not started by serviced with sockets.
    #[error("{0} is not set")]
    Missing(String),
    /// A variable does not have the expected format.
    #[error("{variable} is invalid: {value:?}")]
    Invalid {
        /// The variable.
        variable: String,
        /// Its value.
        value: String,
    },
    /// The sockets were passed to another process, which this one inherited them from.
    #[error("the sockets are for process {listen_pid}, not {pid}")]
    PidMismatch {
        /// `LISTEN_PID`.
        listen_pid: u32,
        /// This process.
        pid: u32,
    },
    /// [`Sockets::from_env`] was already called.
    #[error("the passed sockets were already taken")]
    AlreadyTaken,
    /// A passed fd is closed or is not a socket.
    #[error("fd {fd} ({name}) is not a socket")]
    NotASocket {
        /// The fd.
        fd: RawFd,
        /// Its name.
        name: SocketName,
        /// Why, when it could not be inspected.
        #[source]
        source: Option<io::Error>,
    },
    /// No socket of that name was passed (or it was already taken).
    #[error("no socket named {0:?} was passed")]
    NotPassed(String),
}

/// The sockets serviced passed this process, by name.
#[derive(Debug)]
pub struct Sockets {
    sockets: Vec<ActivatedSocket>,
}

impl Sockets {
    /// Takes the sockets passed to this process, close-on-exec. The variables stay in the
    /// environment, unlike with `sd_listen_fds(1)`: children ignore them, since `LISTEN_PID`
    /// names this process, and they do not inherit the fds.
    ///
    /// # Errors
    ///
    /// When a variable is missing or invalid, `LISTEN_PID` is another process, a fd is not a
    /// socket, or the sockets were already taken.
    pub fn from_env() -> Result<Self, ActivationError> {
        if TAKEN.swap(true, Ordering::SeqCst) {
            return Err(ActivationError::AlreadyTaken);
        }
        let passed = parse(process::id(), |variable| env::var(variable).ok())?;
        let sockets = passed.into_iter().map(take).collect::<Result<_, _>>()?;
        Ok(Self { sockets })
    }

    /// Takes the socket named `name` out of the set.
    ///
    /// # Errors
    ///
    /// When no socket of that name was passed, or it was already taken.
    pub fn take(&mut self, name: &str) -> Result<ActivatedSocket, ActivationError> {
        let index = self
            .sockets
            .iter()
            .position(|socket| socket.name().as_str() == name)
            .ok_or_else(|| ActivationError::NotPassed(name.to_owned()))?;
        Ok(self.sockets.swap_remove(index))
    }
}

/// A socket as the environment describes it, before its fd is taken.
#[derive(Debug, PartialEq, Eq)]
struct Passed {
    fd: RawFd,
    name: SocketName,
    allow: Vec<ServiceName>,
}

/// The sockets passed to process `pid`, from the variables `variable` returns.
fn parse(
    pid: u32,
    variable: impl Fn(&str) -> Option<String>,
) -> Result<Vec<Passed>, ActivationError> {
    let get = |name: &str| variable(name).ok_or_else(|| ActivationError::Missing(name.to_owned()));
    let invalid = |name: &str, value: &str| ActivationError::Invalid {
        variable: name.to_owned(),
        value: value.to_owned(),
    };

    let listen_pid = get(LISTEN_PID)?;
    let listen_pid: u32 = listen_pid
        .parse()
        .map_err(|_| invalid(LISTEN_PID, &listen_pid))?;
    if listen_pid != pid {
        return Err(ActivationError::PidMismatch { listen_pid, pid });
    }
    let count = get(LISTEN_FDS)?;
    let count: RawFd = count
        .parse()
        .ok()
        .filter(|count| (0..=RawFd::MAX - FIRST_FD).contains(count))
        .ok_or_else(|| invalid(LISTEN_FDS, &count))?;
    let names_value = get(LISTEN_FDNAMES)?;
    let names: Vec<SocketName> = if names_value.is_empty() {
        Vec::new()
    } else {
        names_value
            .split(':')
            .map(str::parse)
            .collect::<Result<_, _>>()
            .map_err(|_| invalid(LISTEN_FDNAMES, &names_value))?
    };
    if usize::try_from(count) != Ok(names.len())
        || names
            .iter()
            .enumerate()
            .any(|(index, name)| names[..index].contains(name))
    {
        return Err(invalid(LISTEN_FDNAMES, &names_value));
    }

    (FIRST_FD..)
        .zip(names)
        .map(|(fd, name)| {
            let allow_variable = name.allow_variable();
            let allow_value = get(&allow_variable)?;
            let allow = allow_value
                .split(',')
                .map(str::trim)
                .filter(|service| !service.is_empty())
                .map(str::parse)
                .collect::<Result<_, _>>()
                .map_err(|_| invalid(&allow_variable, &allow_value))?;
            Ok(Passed { fd, name, allow })
        })
        .collect()
}

/// Takes ownership of a passed fd once it is known to be a socket.
fn take(passed: Passed) -> Result<ActivatedSocket, ActivationError> {
    let not_a_socket = |source| ActivationError::NotASocket {
        fd: passed.fd,
        name: passed.name.clone(),
        source,
    };
    // SAFETY: LISTEN_PID names this process, so by the protocol the fds from 3 to
    // 3 + LISTEN_FDS - 1 are the sockets serviced passed it; the borrow does not outlive this
    // function, and the fd is not closed meanwhile.
    let borrowed = unsafe { BorrowedFd::borrow_raw(passed.fd) };
    let stat = rustix::fs::fstat(borrowed).map_err(|errno| not_a_socket(Some(errno.into())))?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::Socket {
        return Err(not_a_socket(None));
    }
    // SAFETY: the fd is an open socket passed to this process (above), which nothing else in it
    // owns: TAKEN makes `Sockets::from_env` the only place taking the passed fds, once.
    let fd = unsafe { OwnedFd::from_raw_fd(passed.fd) };
    rustix::io::fcntl_setfd(&fd, FdFlags::CLOEXEC)
        .map_err(|errno| not_a_socket(Some(errno.into())))?;
    Ok(ActivatedSocket::new(
        passed.name,
        UnixListener::from(fd),
        passed.allow,
    ))
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn parse_with(pid: u32, variables: &[(&str, &str)]) -> Result<Vec<Passed>, ActivationError> {
        let variables: HashMap<_, _> = variables.iter().copied().collect();
        parse(pid, |name| {
            variables.get(name).map(|value| (*value).to_owned())
        })
    }

    #[test]
    fn parses_named_sockets_with_their_allow_lists() {
        let passed = parse_with(
            42,
            &[
                ("LISTEN_PID", "42"),
                ("LISTEN_FDS", "2"),
                ("LISTEN_FDNAMES", "api:machine-admin"),
                ("SERVICED_ALLOW_API", "machine-apiproxy, hctl"),
                ("SERVICED_ALLOW_MACHINE_ADMIN", ""),
            ],
        )
        .expect("valid variables");
        assert_eq!(
            passed,
            [
                Passed {
                    fd: 3,
                    name: "api".parse().unwrap(),
                    allow: vec!["machine-apiproxy".parse().unwrap(), "hctl".parse().unwrap()],
                },
                Passed {
                    fd: 4,
                    name: "machine-admin".parse().unwrap(),
                    allow: Vec::new()
                },
            ]
        );
    }

    #[test]
    fn parses_no_sockets() {
        let passed = parse_with(
            7,
            &[
                ("LISTEN_PID", "7"),
                ("LISTEN_FDS", "0"),
                ("LISTEN_FDNAMES", ""),
            ],
        );
        assert_eq!(passed.expect("valid variables"), []);
    }

    #[test]
    fn rejects_another_process() {
        let error = parse_with(
            7,
            &[
                ("LISTEN_PID", "8"),
                ("LISTEN_FDS", "0"),
                ("LISTEN_FDNAMES", ""),
            ],
        );
        assert!(matches!(
            error,
            Err(ActivationError::PidMismatch {
                listen_pid: 8,
                pid: 7
            })
        ));
    }

    #[test]
    fn rejects_missing_variables() {
        let error = parse_with(7, &[("LISTEN_PID", "7"), ("LISTEN_FDNAMES", "")]);
        assert!(matches!(error, Err(ActivationError::Missing(variable)) if variable == LISTEN_FDS));
        let error = parse_with(
            7,
            &[
                ("LISTEN_PID", "7"),
                ("LISTEN_FDS", "1"),
                ("LISTEN_FDNAMES", "api"),
            ],
        );
        assert!(matches!(
            error,
            Err(ActivationError::Missing(variable)) if variable == "SERVICED_ALLOW_API"
        ));
    }

    #[test]
    fn rejects_invalid_variables() {
        for (pid, count, names, allow) in [
            ("x", "1", "api", "a"),
            ("7", "-1", "", "a"),
            ("7", "2", "api", "a"),
            ("7", "1", "a=b", "a"),
            ("7", "1", "API", "a"),
            ("7", "2", "api:api", "a"),
            ("7", "2", "api:", "a"),
            ("7", "1", "api", "a,Not A Service"),
        ] {
            let error = parse_with(
                7,
                &[
                    ("LISTEN_PID", pid),
                    ("LISTEN_FDS", count),
                    ("LISTEN_FDNAMES", names),
                    ("SERVICED_ALLOW_API", allow),
                ],
            );
            assert!(
                matches!(error, Err(ActivationError::Invalid { .. })),
                "{pid} {count} {names} {allow}: {error:?}"
            );
        }
    }

    #[test]
    fn takes_the_passed_sockets_once() {
        // The first call fails (cargo passes no sockets) but still counts.
        assert!(Sockets::from_env().is_err());
        assert!(matches!(
            Sockets::from_env(),
            Err(ActivationError::AlreadyTaken)
        ));
    }

    #[test]
    fn takes_sockets_by_name() {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let listener = |name: &str| UnixListener::bind(dir.path().join(name)).expect("a socket");
        let mut sockets = Sockets {
            sockets: vec![
                ActivatedSocket::new("api".parse().unwrap(), listener("api"), Vec::new()),
                ActivatedSocket::new("admin".parse().unwrap(), listener("admin"), Vec::new()),
            ],
        };
        assert_eq!(
            sockets.take("admin").expect("passed").name().as_str(),
            "admin"
        );
        assert!(matches!(
            sockets.take("admin"),
            Err(ActivationError::NotPassed(_))
        ));
        assert_eq!(sockets.take("api").expect("passed").name().as_str(), "api");
    }
}

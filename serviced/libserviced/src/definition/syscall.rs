//! A system call a service file allows.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::definition::Error;
use crate::definition::syscall_table::SYSCALLS;

/// An x86-64 system call, named as in Linux's table (`clock_adjtime`), its number resolved once
/// when parsed: its entry in the table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "&'static str")]
pub struct Syscall(&'static (&'static str, i64));

impl Syscall {
    /// Its x86-64 number.
    #[must_use]
    pub fn number(self) -> i64 {
        self.0.1
    }
}

impl FromStr for Syscall {
    type Err = Error;

    fn from_str(name: &str) -> Result<Self, Error> {
        let index = SYSCALLS
            .binary_search_by(|(known, _)| known.cmp(&name))
            .map_err(|_| Error::Invalid(format!("unknown system call {name:?}")))?;
        Ok(Self(&SYSCALLS[index]))
    }
}

impl TryFrom<String> for Syscall {
    type Error = Error;

    fn try_from(name: String) -> Result<Self, Error> {
        name.parse()
    }
}

impl From<Syscall> for &'static str {
    fn from(syscall: Syscall) -> Self {
        syscall.0.0
    }
}

impl Display for Syscall {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.0.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syscalls() {
        let number = |name: &str| name.parse::<Syscall>().map(Syscall::number).ok();
        assert_eq!(number("read"), Some(0));
        assert_eq!(number("socket"), Some(41));
        assert_eq!(number("clock_adjtime"), Some(305));
        assert_eq!(number("clone3"), Some(435));
        assert_eq!(number("socketcall"), None, "not on x86-64");
        let syscall: Syscall = "clock_adjtime".parse().unwrap();
        assert_eq!(syscall.to_string(), "clock_adjtime");
        assert!(
            SYSCALLS.windows(2).all(|pair| pair[0].0 < pair[1].0),
            "sorted, for the binary search"
        );
    }
}

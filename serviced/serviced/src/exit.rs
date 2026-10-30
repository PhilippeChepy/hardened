//! How a process ended.

use std::fmt::{self, Display, Formatter};

/// How a process ended: its exit code, or the signal that killed it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

impl Exit {
    /// Whether the process exited with 0.
    #[must_use]
    pub fn success(self) -> bool {
        self == Self::Code(0)
    }
}

impl Display for Exit {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Code(code) => write!(f, "exit code {code}"),
            Self::Signal(signal) => write!(f, "signal {signal}"),
        }
    }
}

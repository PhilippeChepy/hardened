//! Why a service, its name, or one of its files is rejected.

use std::io;
use std::path::PathBuf;

use crate::definition::ServiceName;

/// An invalid service or value of a service file, or a service file that cannot be read.
#[derive(Debug, thiserror::Error)]
#[must_use]
#[allow(missing_docs, reason = "self-explanatory fields")]
pub enum Error {
    /// An invalid value (a name, a path, a system call...), or a service breaking a rule across
    /// its fields.
    #[error("{0}")]
    Invalid(String),
    /// A file or directory that cannot be read.
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: io::Error },
    /// A file that is not TOML.
    #[error("{}: {source}", path.display())]
    Toml {
        path: PathBuf,
        source: toml::de::Error,
    },
    /// A file of the image's layer, which services do not write.
    #[error("the image's service files are read-only")]
    ReadOnly,
    /// A file or directory that cannot be written or removed.
    #[error("{}: {source}", path.display())]
    Write { path: PathBuf, source: io::Error },
    /// The error of service `name`.
    #[error("service {name}: {source}")]
    Service {
        name: ServiceName,
        source: Box<Error>,
    },
}

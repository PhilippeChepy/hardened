//! serviced's service files: their format ([`Service`]), their three layers and how files of
//! the same name merge ([`load`]), writing them ([`write_service_file`]), and where services'
//! logs go ([`log_path`]).

mod absolute_path;
mod capability;
mod command;
mod error;
mod layer;
mod paths;
mod sandbox;
mod service;
mod service_name;
mod socket_name;
mod syscall;
mod syscall_table;
mod write_service_file;

pub use absolute_path::AbsolutePath;
pub use capability::Capability;
pub use command::Command;
pub use error::Error;
pub use layer::{Layer, Loaded, load, merge_service, read_service_file, service_file};
pub use paths::{LogDir, RUN_LOG_DIR, RUNTIME_DIR, VAR_LOG_DIR, log_path};
pub use sandbox::{Bind, Binds, Limits, Sandbox, SocketFamily};
pub use service::{Access, Condition, Restart, Service, Socket};
pub use service_name::ServiceName;
pub use socket_name::SocketName;
pub use syscall::Syscall;
pub use write_service_file::{remove_service_file, write_service_file};

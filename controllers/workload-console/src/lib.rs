//! workload-console's API (`hardened.console.v1`, on [`SOCKET`]) and its validated values.

#![warn(missing_docs)]

mod exec_process;
mod socket;
mod terminal_size;

/// The code prost and tonic generate from `proto/`, whose comments document what it covers.
#[allow(missing_docs)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/hardened.rs"));
}

pub use exec_process::ExecProcess;
pub use generated::hardened::console::v1 as console;
pub use socket::SOCKET;
pub use terminal_size::TerminalSize;

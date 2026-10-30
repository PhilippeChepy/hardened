//! Socket activation: the listening sockets serviced creates for a service and passes it as
//! systemd does (fds from 3, `LISTEN_FDS`, `LISTEN_PID`, `LISTEN_FDNAMES`), each with the services
//! allowed to call it in `SERVICED_ALLOW_<NAME>`.

mod activated_socket;
mod sockets;

pub use activated_socket::ActivatedSocket;
pub use sockets::ActivationError;
pub use sockets::FIRST_FD;
pub use sockets::LISTEN_FDNAMES;
pub use sockets::LISTEN_FDS;
pub use sockets::LISTEN_PID;
pub use sockets::Sockets;

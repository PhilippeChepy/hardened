use std::os::unix::net::UnixListener;

use crate::definition::ServiceName;
use crate::definition::SocketName;

/// A listening socket of the service, with the services allowed to call it.
#[derive(Debug)]
pub struct ActivatedSocket {
    name: SocketName,
    allow: Vec<ServiceName>,
    listener: UnixListener,
}

impl ActivatedSocket {
    /// A socket bound by the service itself (tests), whose callers `allow` lists.
    #[must_use]
    pub fn new(name: SocketName, listener: UnixListener, allow: Vec<ServiceName>) -> Self {
        Self {
            name,
            allow,
            listener,
        }
    }

    /// The socket's name, from its service file.
    #[must_use]
    pub fn name(&self) -> &SocketName {
        &self.name
    }

    /// The name, allow-list and listening socket.
    #[must_use]
    pub(crate) fn into_parts(self) -> (SocketName, Vec<ServiceName>, UnixListener) {
        (self.name, self.allow, self.listener)
    }
}

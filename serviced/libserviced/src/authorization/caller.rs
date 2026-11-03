use crate::definition::ServiceName;

/// The service on the other end of a connection, as serviced identified it when the connection
/// was accepted. tonic puts it in the extensions of each of the connection's requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Caller {
    service: ServiceName,
    pid: u32,
    uid: u32,
}

impl Caller {
    /// A caller of `service`, connected from process `pid` running as user `uid`.
    #[must_use]
    pub fn new(service: ServiceName, pid: u32, uid: u32) -> Self {
        Self { service, pid, uid }
    }

    /// The calling service of `request`; `None` when it was not served by
    /// [`serve`](crate::authorization::serve).
    #[must_use]
    pub fn of<T>(request: &tonic::Request<T>) -> Option<&Self> {
        request.extensions().get()
    }

    /// The calling service's name.
    #[must_use]
    pub fn service(&self) -> &ServiceName {
        &self.service
    }

    /// The user the connecting process ran as (`SO_PEERCRED`): a service's processes may run as
    /// several, such as a login service's sessions as their users.
    #[must_use]
    pub fn uid(&self) -> u32 {
        self.uid
    }

    /// The process that connected.
    #[must_use]
    pub(crate) fn pid(&self) -> u32 {
        self.pid
    }
}

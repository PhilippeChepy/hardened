//! What serviced's API asks of the supervisor, which owns the services.

use libserviced::definition::ServiceName;
use tokio::sync::oneshot;

use crate::engine::Refusal;

/// A request to the supervisor, answered once carried out.
#[derive(Debug)]
pub enum Command {
    Start(ServiceName, oneshot::Sender<Result<(), Refusal>>),
    Stop(ServiceName, oneshot::Sender<Result<(), Refusal>>),
    Restart(ServiceName, oneshot::Sender<Result<(), Refusal>>),
    /// Read the service files again and reconcile; answers why services are left out.
    Reload(oneshot::Sender<Vec<String>>),
}

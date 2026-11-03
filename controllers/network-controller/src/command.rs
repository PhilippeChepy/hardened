//! What the API asks of the task configuring the interfaces ([`Interfaces`](crate::interfaces::Interfaces)),
//! which alone changes them, one request at a time.

use network_controller::InterfaceName;
use network_controller::InterfaceSettings;
use network_controller::network;
use tokio::sync::mpsc;
use tokio::sync::oneshot;
use tonic::Status;

/// A request to the interfaces' task, with where to answer.
pub enum Command {
    /// The interfaces present and configured, sorted by name.
    List(oneshot::Sender<Vec<network::Interface>>),
    /// Applies and keeps `settings` for the interface `name`, the default configuration when
    /// `None`; answers the interface as it is then.
    Configure {
        name: InterfaceName,
        settings: Option<InterfaceSettings>,
        reply: oneshot::Sender<Result<network::Interface, ConfigureError>>,
    },
}

/// Why a configuration was refused or undone.
#[derive(Debug, thiserror::Error)]
pub enum ConfigureError {
    /// The interface exists, but network-controller does not configure it.
    #[error("{0} is not a physical Ethernet interface")]
    NotPhysical(InterfaceName),
    /// An address is another interface's.
    #[error("{0}")]
    Conflict(String),
    /// It could not be applied: the previous configuration was restored.
    #[error("{0:#}")]
    Applying(anyhow::Error),
    /// It could not be kept: the previous configuration was restored.
    #[error("{0:#}")]
    Persisting(anyhow::Error),
}

impl From<ConfigureError> for Status {
    fn from(error: ConfigureError) -> Self {
        let message = error.to_string();
        match error {
            ConfigureError::NotPhysical(_) => Status::not_found(message),
            ConfigureError::Conflict(_) => Status::failed_precondition(message),
            ConfigureError::Applying(_) => Status::aborted(format!(
                "{message} (the previous configuration was restored)"
            )),
            ConfigureError::Persisting(_) => Status::internal(format!(
                "{message} (the previous configuration was restored)"
            )),
        }
    }
}

/// Sends the interfaces' task its [`Command`]s.
#[derive(Clone)]
pub struct Commands(mpsc::Sender<Command>);

impl Commands {
    /// Commands for the receiver of `sender`.
    #[must_use]
    pub fn new(sender: mpsc::Sender<Command>) -> Self {
        Self(sender)
    }

    /// The interfaces present and configured.
    pub async fn list(&self) -> Result<Vec<network::Interface>, Status> {
        let (reply, answer) = oneshot::channel();
        self.send(Command::List(reply)).await?;
        answer.await.map_err(|_| gone())
    }

    /// Applies and keeps `settings` for `name` (see [`Command::Configure`]).
    pub async fn configure(
        &self,
        name: InterfaceName,
        settings: Option<InterfaceSettings>,
    ) -> Result<network::Interface, Status> {
        let (reply, answer) = oneshot::channel();
        let command = Command::Configure {
            name,
            settings,
            reply,
        };
        self.send(command).await?;
        Ok(answer.await.map_err(|_| gone())??)
    }

    async fn send(&self, command: Command) -> Result<(), Status> {
        self.0.send(command).await.map_err(|_| gone())
    }
}

/// The interfaces' task stopped: only a failure of its link notifications ends it.
fn gone() -> Status {
    Status::unavailable("network-controller no longer follows the interfaces")
}

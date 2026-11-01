//! Clients of serviced's API.

use std::path::Path;

use tonic::transport::Channel;

use crate::SOCKET;
use crate::api;
use crate::unix_channel;

/// A client of serviced's API on [`SOCKET`].
///
/// # Errors
///
/// When the socket cannot be connected to.
pub async fn connect()
-> Result<api::serviced_client::ServicedClient<Channel>, tonic::transport::Error> {
    connect_to(Path::new(SOCKET)).await
}

/// A client of serviced's API on `socket` (tests use their own).
///
/// # Errors
///
/// When the socket cannot be connected to.
pub async fn connect_to(
    socket: &Path,
) -> Result<api::serviced_client::ServicedClient<Channel>, tonic::transport::Error> {
    Ok(api::serviced_client::ServicedClient::new(
        unix_channel::connect(socket).await?,
    ))
}

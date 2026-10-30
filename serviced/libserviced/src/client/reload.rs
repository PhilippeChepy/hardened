use tonic::Status;
use tonic::transport::Channel;

use crate::api::serviced_client::ServicedClient;
use crate::client;

/// Asks serviced to read the service files again, after writing or removing some: once it
/// answers, the sockets of the enabled services exist. The files serviced leaves out, whoever
/// wrote them, are logged.
///
/// # Errors
///
/// serviced's failures, as [`call_error`](client::call_error) makes them.
pub async fn reload(serviced: &mut ServicedClient<Channel>) -> Result<(), Status> {
    let response = serviced
        .reload(())
        .await
        .map_err(|status| client::call_error("Reload", status))?;
    for invalid in response.into_inner().invalid {
        tracing::warn!(%invalid, "serviced left a service out");
    }
    Ok(())
}

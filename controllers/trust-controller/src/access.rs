//! Which service may call which method: each of the socket's APIs has one client.

use libserviced::authorization::Caller;
use tonic::Request;
use tonic::Status;

/// Fails with PERMISSION_DENIED unless `request` comes from `service`. The socket's allow-list
/// lets in every client of every API on it; this keeps each to its own.
pub fn require<T>(request: &Request<T>, service: &str) -> Result<(), Status> {
    match Caller::of(request) {
        Some(caller) if caller.service().as_str() == service => Ok(()),
        Some(caller) => Err(Status::permission_denied(format!(
            "{} may not call this method",
            caller.service()
        ))),
        None => Err(Status::permission_denied("unidentified caller")),
    }
}

/// A request from `service`.
#[cfg(test)]
pub fn from<T>(service: &str, message: T) -> Request<T> {
    let mut request = Request::new(message);
    request
        .extensions_mut()
        .insert(Caller::new(service.parse().unwrap(), 1));
    request
}

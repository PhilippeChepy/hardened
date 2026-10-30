use tonic::Code;
use tonic::Status;

/// An unexpected failure of serviced's `call`, as the client's own callers see it: `unavailable`
/// stays so (it may be retried), anything else is the client's `internal` failure (a
/// `permission_denied` from serviced is about the client, not about its caller).
#[must_use]
pub fn call_error(call: &str, status: Status) -> Status {
    let message = format!("serviced's {call}: {}", status.message());
    match status.code() {
        Code::Unavailable => Status::unavailable(message),
        _ => Status::internal(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_unavailable_stays() {
        let status = call_error("Start", Status::unavailable("restarting"));
        assert_eq!(status.code(), Code::Unavailable);
        assert_eq!(status.message(), "serviced's Start: restarting");
        let status = call_error("Start", Status::permission_denied("no control"));
        assert_eq!(status.code(), Code::Internal);
    }
}

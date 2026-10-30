//! Serving a gRPC API on an [activated socket](crate::activation::ActivatedSocket) to the
//! services its allow-list names. Each connection's peer is identified when it is accepted, by
//! asking serviced's `IdentifyProcess` about its pid (`SO_PEERCRED`), and dropped unless its
//! service is allowed; handlers read it as a [`Caller`] in the request's extensions.

mod caller;
mod caller_stream;
mod incoming;
mod serve;

pub use caller::Caller;
pub use caller_stream::CallerStream;
pub(crate) use incoming::Incoming;
pub use serve::ServeError;
pub use serve::serve;

//! What clients of serviced's API share: how its failures reach their own callers, and reloading
//! the service files they wrote.

mod call_error;
mod reload;

pub use call_error::call_error;
pub use reload::reload;

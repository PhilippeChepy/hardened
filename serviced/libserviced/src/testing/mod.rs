//! A fake serviced for the tests of its clients (feature `testing`).

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "test support: a failure is the failing test's"
)]

mod fake_serviced;

pub use fake_serviced::Call;
pub use fake_serviced::FakeServiced;

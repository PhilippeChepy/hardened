//! The settings model, and user-data: its transport encodings and its document.
//!
//! User-data is TOML (`[settings.<group>]`, kebab-case keys), with Bottlerocket's groups, keys and
//! value formats where it has the setting, and hardened's own under `[settings.hardened]`. Unknown
//! keys are rejected, so a typo is an error rather than a setting silently ignored. Every field
//! has a type admitting only valid values, and values that only make sense together are held
//! together: where Bottlerocket writes them apart (a module's two flags, soft eviction thresholds
//! and their grace periods), they are read as written, then checked into one value. Parsing is
//! validation. Each controller's part of the settings is its own type, in its crate.

mod encoding;
mod kernel_settings;
mod registry_settings;
#[allow(
    clippy::module_inception,
    reason = "the module of `Settings`, the root of the others"
)]
mod settings;
mod settings_message;
mod user_data;

pub use kernel_settings::{KernelSettings, ModuleLoad};
pub use registry_settings::{Auth, Endpoint, Registry, RegistrySettings};
pub use settings::{NtpSettings, Settings, TimeSettings};
pub use user_data::{Error, UserData};

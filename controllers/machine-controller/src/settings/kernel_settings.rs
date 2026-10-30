//! `[settings.kernel]`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::{ModuleName, SysctlKey};

/// `[settings.kernel]`: sysctls and kernel modules.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct KernelSettings {
    /// Extra sysctls, applied after (and able to override) the hardened defaults.
    #[serde(default)]
    pub sysctl: BTreeMap<SysctlKey, String>,
    /// When machine-controller loads modules shipped in the image, keyed by module name. One
    /// left out is [`ModuleLoad::AsDependency`].
    #[serde(default)]
    pub modules: BTreeMap<ModuleName, ModuleLoad>,
}

/// When machine-controller loads a kernel module. The kernel never loads modules by itself (no
/// modprobe helper): this only steers machine-controller.
///
/// Written as Bottlerocket's `[settings.kernel.modules.<name>]`: `allowed` (true by default) and
/// `autoload` (false by default); a module autoloaded but not allowed is rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "ModuleFlags", into = "ModuleFlags")]
pub enum ModuleLoad {
    /// Never, not even as a dependency: a module loaded at boot needing it is not loaded either
    /// (`allowed = false`).
    Never,
    /// When a module loaded at boot needs it.
    AsDependency,
    /// At boot, with its dependencies (`autoload = true`).
    AtBoot,
}

/// [`ModuleLoad`] as Bottlerocket writes it.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields, expecting = "a table of `allowed` and `autoload`")]
struct ModuleFlags {
    #[serde(default = "allowed_by_default")]
    allowed: bool,
    #[serde(default)]
    autoload: bool,
}

#[must_use]
fn allowed_by_default() -> bool {
    true
}

impl TryFrom<ModuleFlags> for ModuleLoad {
    type Error = &'static str;

    fn try_from(flags: ModuleFlags) -> Result<Self, Self::Error> {
        match (flags.allowed, flags.autoload) {
            (false, false) => Ok(Self::Never),
            (true, false) => Ok(Self::AsDependency),
            (true, true) => Ok(Self::AtBoot),
            (false, true) => Err("a module cannot be autoloaded when it is not allowed"),
        }
    }
}

impl From<ModuleLoad> for ModuleFlags {
    fn from(load: ModuleLoad) -> Self {
        Self {
            allowed: load != ModuleLoad::Never,
            autoload: load == ModuleLoad::AtBoot,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modules(text: &str) -> Result<BTreeMap<ModuleName, ModuleLoad>, toml::de::Error> {
        toml::from_str::<KernelSettings>(text).map(|kernel| kernel.modules)
    }

    #[test]
    fn modules_take_bottlerocket_flags_and_round_trip() {
        let modules = modules(
            "[modules.wireguard]\nautoload = true\n\
             [modules.sctp]\nallowed = false\n\
             [modules.tun]\n\
             [modules.dummy]\nallowed = true\nautoload = false\n",
        )
        .unwrap();
        assert_eq!(modules["wireguard"], ModuleLoad::AtBoot);
        assert_eq!(modules["sctp"], ModuleLoad::Never);
        assert_eq!(modules["tun"], ModuleLoad::AsDependency);
        assert_eq!(modules["dummy"], ModuleLoad::AsDependency);
        for load in [
            ModuleLoad::Never,
            ModuleLoad::AsDependency,
            ModuleLoad::AtBoot,
        ] {
            let text = toml::to_string(&load).unwrap();
            assert_eq!(toml::from_str::<ModuleLoad>(&text).unwrap(), load, "{text}");
        }
    }

    #[test]
    fn rejects_an_autoloaded_module_not_allowed() {
        let error = modules("[modules.sctp]\nallowed = false\nautoload = true\n").unwrap_err();
        assert!(error.to_string().contains("not allowed"), "{error}");
    }
}

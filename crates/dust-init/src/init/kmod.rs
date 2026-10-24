//! Kernel modules: pinning where they may come from, and loading the ones requested in user-data
//! (with their dependencies), using `modules.dep` generated at build time. The kernel has no
//! modprobe helper, so it never loads modules by itself.
//!
//! The kernel checks module signatures, and LoadPin restricts every file it loads (modules,
//! firmware) to the filesystem of the first one, which [`pin`] makes the dm-verity root.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use tracing::{info, warn};

use crate::settings::ModuleSettings;
use crate::types::ModuleName;

/// Pins LoadPin to the root filesystem before anything else can load a kernel file: otherwise a
/// privileged workload loading the first module from `/var` would pin that filesystem instead.
/// LoadPin pins when it checks the file, before the kernel reads it as a module, so a regular
/// file of the root does (the kernel then rejects it as unsigned).
pub fn pin() {
    let result = rustix::fs::open(
        PIN_FILE,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .and_then(|file| rustix::system::finit_module(&file, c"", 0));
    match result {
        Err(rustix::io::Errno::KEYREJECTED | rustix::io::Errno::NOEXEC | rustix::io::Errno::INVAL) => {
            info!("kernel files pinned to the root filesystem")
        }
        Ok(()) => warn!("{PIN_FILE} loaded as a kernel module"),
        Err(e) => warn!("cannot pin kernel files to the root filesystem: {e}"),
    }
}

/// A regular file of the root filesystem, never a module.
const PIN_FILE: &str = "/usr/lib/os-release";

pub fn load(modules: &BTreeMap<ModuleName, ModuleSettings>) {
    let requested: Vec<&ModuleName> = modules.iter().filter(|(_, m)| m.autoload).map(|(n, _)| n).collect();
    if requested.is_empty() {
        return;
    }
    let release = rustix::system::uname().release().to_string_lossy().into_owned();
    let dir = PathBuf::from("/usr/lib/modules").join(release);
    let index = match Index::read(&dir) {
        Ok(index) => index,
        Err(e) => {
            warn!("cannot load kernel modules: {e:#}");
            return;
        }
    };
    let denied: BTreeSet<String> = modules
        .iter()
        .filter(|(_, m)| !m.allowed)
        .map(|(name, _)| name.canonical())
        .collect();
    let mut loaded = BTreeSet::new();
    for name in requested {
        match index.load(&dir, name, &denied, &mut loaded) {
            Ok(()) => info!(module = %name, "kernel module loaded"),
            Err(e) => warn!(module = %name, "cannot load kernel module: {e:#}"),
        }
    }
}

/// `modules.dep`: module path → dependency paths, keyed by module name.
struct Index {
    modules: BTreeMap<String, (String, Vec<String>)>,
}

impl Index {
    fn read(dir: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(dir.join("modules.dep")).context("reading modules.dep")?;
        Ok(Self::parse(&text))
    }

    fn parse(text: &str) -> Self {
        let modules = text
            .lines()
            .filter_map(|line| {
                let (path, deps) = line.split_once(':')?;
                Some((
                    module_name(path),
                    (path.to_owned(), deps.split_whitespace().map(str::to_owned).collect()),
                ))
            })
            .collect();
        Self { modules }
    }

    /// Loads `name` and its dependencies, unless one of them is `denied` (canonical names).
    fn load(
        &self,
        dir: &Path,
        name: &ModuleName,
        denied: &BTreeSet<String>,
        loaded: &mut BTreeSet<String>,
    ) -> anyhow::Result<()> {
        let modules = self.closure(name)?;
        if let Some(module) = modules
            .iter()
            .map(|path| module_name(path))
            .find(|m| denied.contains(m))
        {
            bail!("needs {module}, which is not allowed");
        }
        for path in modules {
            if loaded.insert(path.to_owned()) {
                insert(&dir.join(path))?;
            }
        }
        Ok(())
    }

    /// The module files to insert for `name`, in order: its dependencies, then itself.
    fn closure(&self, name: &ModuleName) -> anyhow::Result<Vec<&str>> {
        let Some((path, deps)) = self.modules.get(&name.canonical()) else {
            bail!("unknown module");
        };
        // modules.dep lists the full transitive closure, dependencies of dependencies first.
        Ok(deps
            .iter()
            .rev()
            .chain(std::iter::once(path))
            .map(String::as_str)
            .collect())
    }
}

/// Canonical module name: file stem with dashes replaced by underscores.
fn module_name(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.split('.').next().unwrap_or(file).replace('-', "_")
}

fn insert(path: &Path) -> anyhow::Result<()> {
    let file = std::fs::File::open(path).with_context(|| path.display().to_string())?;
    match rustix::system::finit_module(&file, c"", 0) {
        Ok(()) | Err(rustix::io::Errno::EXIST) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("finit_module {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modules_dep() {
        let index = Index::parse(
            "kernel/drivers/net/wireguard/wireguard.ko: kernel/net/ipv4/udp_tunnel.ko kernel/net/ipv6/ip6_udp_tunnel.ko\n\
             kernel/net/ipv4/udp_tunnel.ko:\n",
        );
        let (path, deps) = &index.modules["wireguard"];
        assert_eq!(path, "kernel/drivers/net/wireguard/wireguard.ko");
        assert_eq!(deps.len(), 2);
        assert_eq!(module_name("kernel/x/mlx5-core.ko"), "mlx5_core");
        assert_eq!(
            index.closure(&"wireguard".parse().unwrap()).unwrap(),
            [
                "kernel/net/ipv6/ip6_udp_tunnel.ko",
                "kernel/net/ipv4/udp_tunnel.ko",
                "kernel/drivers/net/wireguard/wireguard.ko"
            ]
        );
    }

    #[test]
    fn refuses_modules_needing_a_denied_one() {
        let index = Index::parse("kernel/net/wireguard.ko: kernel/net/udp-tunnel.ko\nkernel/net/udp-tunnel.ko:\n");
        let denied = BTreeSet::from(["udp_tunnel".to_owned()]);
        let mut loaded = BTreeSet::new();
        let error = index
            .load(
                Path::new("/nonexistent"),
                &"wireguard".parse().unwrap(),
                &denied,
                &mut loaded,
            )
            .unwrap_err();
        assert_eq!(error.to_string(), "needs udp_tunnel, which is not allowed");
        assert!(loaded.is_empty(), "nothing is inserted");
    }
}

//! Kernel modules: loading the ones requested in user-data (with their dependencies), using
//! `modules.dep` generated at build time. The kernel has no modprobe helper, so it never loads
//! modules by itself.
//!
//! The kernel checks module signatures, and LoadPin restricts every file it loads (modules,
//! firmware) to the filesystem of the first one, which serviced makes the dm-verity root.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::bail;
use machine_controller::ModuleLoad;
use machine_controller::ModuleName;
use rustix::io::Errno;
use tracing::info;
use tracing::warn;

use crate::machine_identity;

/// Loads the modules user-data loads at boot, with their dependencies, unless one of them is
/// never loaded; a module that cannot be loaded is logged and skipped.
pub fn load(modules: &BTreeMap<ModuleName, ModuleLoad>) {
    let mut requested = Vec::new();
    let mut denied = BTreeSet::new();
    for (name, load) in modules {
        match load {
            ModuleLoad::AtBoot => requested.push(name),
            ModuleLoad::AsDependency => {}
            ModuleLoad::Never => {
                denied.insert(name.to_canonical());
            }
        }
    }
    if requested.is_empty() {
        return;
    }
    let dir = PathBuf::from("/usr/lib/modules").join(machine_identity::kernel_release());
    let index = match Index::read(dir) {
        Ok(index) => index,
        Err(e) => {
            warn!("cannot load kernel modules: {e:#}");
            return;
        }
    };
    let mut loaded = BTreeSet::new();
    for name in requested {
        match index.load(name, &denied, &mut loaded) {
            Ok(()) => info!(module = %name, "kernel module loaded"),
            Err(e) => warn!(module = %name, "cannot load kernel module: {e:#}"),
        }
    }
}

/// `modules.dep` of a modules directory: the modules, keyed by canonical name.
struct Index {
    dir: PathBuf,
    modules: BTreeMap<String, IndexEntry>,
}

/// A line of `modules.dep`.
struct IndexEntry {
    /// The module file, relative to the modules directory.
    path: String,
    /// Its module files' dependencies, transitively.
    dependencies: Vec<String>,
}

impl Index {
    fn read(dir: PathBuf) -> anyhow::Result<Self> {
        let text = fs::read_to_string(dir.join("modules.dep")).context("reading modules.dep")?;
        Ok(Self::parse(dir, &text))
    }

    #[must_use]
    fn parse(dir: PathBuf, text: &str) -> Self {
        let mut modules = BTreeMap::new();
        for line in text.lines() {
            if let Some((path, dependencies)) = line.split_once(':') {
                let entry = IndexEntry {
                    path: path.to_owned(),
                    dependencies: dependencies.split_whitespace().map(str::to_owned).collect(),
                };
                modules.insert(module_name(path), entry);
            }
        }
        Self { dir, modules }
    }

    /// Loads `name` and its dependencies, unless one of them is `denied` (canonical names).
    fn load(
        &self,
        name: &ModuleName,
        denied: &BTreeSet<String>,
        loaded: &mut BTreeSet<String>,
    ) -> anyhow::Result<()> {
        let modules = self.closure(name)?;
        for path in &modules {
            let module = module_name(path);
            if denied.contains(&module) {
                bail!("needs {module}, which is never loaded");
            }
        }
        for path in modules {
            if loaded.insert(path.to_owned()) {
                insert(&self.dir.join(path))?;
            }
        }
        Ok(())
    }

    /// The module files to insert for `name`, in order: its dependencies, then itself.
    fn closure(&self, name: &ModuleName) -> anyhow::Result<Vec<&str>> {
        let Some(entry) = self.modules.get(&name.to_canonical()) else {
            bail!("unknown module");
        };
        // modules.dep lists the full transitive closure, dependencies of dependencies last.
        let mut modules: Vec<&str> = entry
            .dependencies
            .iter()
            .rev()
            .map(String::as_str)
            .collect();
        modules.push(&entry.path);
        Ok(modules)
    }
}

/// The canonical name of a module file: its stem, dashes replaced by underscores.
#[must_use]
fn module_name(path: &str) -> String {
    let file = path.rsplit('/').next().unwrap_or(path);
    file.split('.').next().unwrap_or(file).replace('-', "_")
}

/// Inserts the module file at `path`; inserted already, it is left as is.
fn insert(path: &Path) -> anyhow::Result<()> {
    let file = File::open(path).with_context(|| path.display().to_string())?;
    match rustix::system::finit_module(&file, c"", 0) {
        Ok(()) | Err(Errno::EXIST) => Ok(()),
        Err(e) => Err(e).with_context(|| format!("finit_module {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_modules_dep() {
        let index = Index::parse(
            PathBuf::new(),
            "kernel/drivers/net/wireguard/wireguard.ko: kernel/net/ipv4/udp_tunnel.ko \
             kernel/net/ipv6/ip6_udp_tunnel.ko\n\
             kernel/net/ipv4/udp_tunnel.ko:\n",
        );
        let wireguard = &index.modules["wireguard"];
        assert_eq!(wireguard.path, "kernel/drivers/net/wireguard/wireguard.ko");
        assert_eq!(wireguard.dependencies.len(), 2);
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
        let index = Index::parse(
            PathBuf::from("/nonexistent"),
            "kernel/net/wireguard.ko: kernel/net/udp-tunnel.ko\nkernel/net/udp-tunnel.ko:\n",
        );
        let denied = BTreeSet::from(["udp_tunnel".to_owned()]);
        let mut loaded = BTreeSet::new();
        let error = index
            .load(&"wireguard".parse().unwrap(), &denied, &mut loaded)
            .unwrap_err();
        assert_eq!(error.to_string(), "needs udp_tunnel, which is never loaded");
        assert!(loaded.is_empty(), "nothing is inserted");
    }
}

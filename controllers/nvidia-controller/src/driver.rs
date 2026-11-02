//! NVIDIA's driver as the image ships it, in `/usr/lib/nvidia/<version>`: its signed modules,
//! which the kernel only loads from the verity root (LoadPin); their GSP firmware is in
//! `/usr/lib/firmware/nvidia/<version>`, where the kernel finds it.

use std::fs::File;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context as _;
use rustix::io::Errno;

/// The modules, in loading order: nvidia-uvm needs nvidia's symbols.
const MODULES: [&str; 2] = ["nvidia", "nvidia-uvm"];

/// The driver of the directory `dir`, named after its version.
#[derive(Debug, Clone)]
pub struct Driver {
    dir: PathBuf,
}

impl Driver {
    /// The driver in `dir` (`/usr/lib/nvidia/<version>`).
    #[must_use]
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    /// Its version, its directory's name.
    #[must_use]
    pub fn version(&self) -> String {
        self.dir
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_default()
    }

    /// Its user space, the driver root (glibc's, for containers and `nvidia-smi`).
    #[must_use]
    pub fn root(&self) -> PathBuf {
        self.dir.join("root")
    }

    /// Loads its modules; loaded already, they are left as they are.
    ///
    /// # Errors
    ///
    /// When a module cannot be read or the kernel refuses it (a probe failure included).
    pub fn load(&self) -> anyhow::Result<()> {
        for module in MODULES {
            let path = self.dir.join("modules").join(format!("{module}.ko"));
            insert(&path)?;
            tracing::info!(module, "kernel module loaded");
        }
        Ok(())
    }
}

/// Inserts the module at `path`, without parameters.
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
    fn named_after_its_directory() {
        let driver = Driver::new(PathBuf::from("/usr/lib/nvidia/595.112.07"));
        assert_eq!(driver.version(), "595.112.07");
    }
}

//! Where the build reads and writes, below the repository.

use std::path::PathBuf;

use anyhow::Context;

/// Well-known locations, relative to the repository root.
#[derive(Debug, Clone)]
pub struct Paths {
    /// The repository's root.
    pub root: PathBuf,
}

impl Paths {
    /// The locations of the repository image-builder was built from.
    ///
    /// # Errors
    ///
    /// When image-builder is not at the root of a repository.
    pub fn discover() -> anyhow::Result<Self> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir
            .ancestors()
            .nth(1)
            .context("image-builder must live at the root of the repository")?
            .to_path_buf();
        Ok(Self { root })
    }

    /// The build's specifications: `components/` (the recipes) and `targets/`.
    #[must_use]
    pub fn specs(&self) -> PathBuf {
        self.root.join("specs")
    }

    /// The targets, each with its components (`specs/targets/`).
    #[must_use]
    pub fn targets(&self) -> PathBuf {
        self.specs().join("targets")
    }

    /// What builds write (`build/`): disposable but for the keys.
    #[must_use]
    pub fn build(&self) -> PathBuf {
        self.root.join("build")
    }

    /// Downloaded sources, by checksum.
    #[must_use]
    pub fn sources(&self) -> PathBuf {
        self.build().join("cache/sources")
    }

    /// Downloads and other caches shared by builds.
    #[must_use]
    pub fn cache(&self) -> PathBuf {
        self.build().join("cache")
    }

    /// The components built, by component and hash.
    #[must_use]
    pub fn outputs(&self) -> PathBuf {
        self.build().join("components")
    }

    /// The work directories of the builds in progress.
    #[must_use]
    pub fn work(&self) -> PathBuf {
        self.build().join("work")
    }

    /// Where the image of `target` is assembled.
    #[must_use]
    pub fn image(&self, target: &str) -> PathBuf {
        self.build().join("image").join(target)
    }

    /// The published images and their SBOMs.
    #[must_use]
    pub fn out(&self) -> PathBuf {
        self.build().join("out")
    }

    /// Build logs: one per component and per environment, overwritten by each build.
    #[must_use]
    pub fn logs(&self) -> PathBuf {
        self.build().join("logs")
    }

    /// The Secure Boot and module signing keys, and the randstruct seed: kept across builds.
    #[must_use]
    pub fn keys(&self) -> PathBuf {
        self.build().join("keys")
    }

    /// Takes the exclusive lock on `build/`, held until the returned file is dropped: two
    /// builders would delete each other's work directories.
    pub fn lock(&self) -> anyhow::Result<std::fs::File> {
        std::fs::create_dir_all(self.build())?;
        let path = self.build().join(".lock");
        let file = std::fs::File::create(&path).with_context(|| path.display().to_string())?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                anyhow::bail!("another image-builder is using {}", self.build().display())
            }
            Err(std::fs::TryLockError::Error(e)) => Err(e).context(path.display().to_string()),
        }
    }
}

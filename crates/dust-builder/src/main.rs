//! The hardened build system.
//!
//! Every component of the OS is compiled from source inside a pinned builder image
//! (`builder/Containerfile`), then assembled into a dm-verity protected root filesystem, a signed
//! unified kernel image and a GPT disk, published as qcow2 together with a CycloneDX SBOM.
//!
//! ```text
//! cargo builder image          # build everything, write build/out/
//! cargo builder run            # boot the image in qemu (OVMF + swtpm)
//! cargo builder test           # boot it headless and check the smoke-test markers
//! ```

mod build;
mod components;
mod exec;
mod fetch;
mod image;
mod keys;
mod oci;
mod podman;
mod recipe;
mod report;
mod rootfs;
mod run;
mod sbom;
mod sha256;

use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};

/// Timestamp of every reproducible output (file mtimes, kernel build date...): 2026-01-01.
///
/// A constant rather than the commit date, so unrelated commits do not invalidate cached builds.
pub const SOURCE_DATE_EPOCH: u64 = 1_767_225_600;

#[derive(Parser)]
#[command(about = "Build, assemble and run the hardened OS image")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Builds the builder image (done implicitly by the other commands).
    Builder,
    /// Downloads and verifies the source archives of all components.
    Fetch,
    /// Builds components (all by default) and their dependencies.
    Build {
        components: Vec<recipe::ComponentName>,
        /// Rebuild the named components even if cached.
        #[arg(long)]
        force: bool,
    },
    /// Prints the scripts a component's recipe renders to, without running anything.
    Plan { component: recipe::ComponentName },
    /// Builds everything and writes the qcow2 image and its SBOM to build/out/.
    Image,
    /// Boots the image in qemu with a serial console.
    Run(run::RunArgs),
    /// Builds the image, boots it headless and waits for the smoke-test markers.
    Test(run::TestArgs),
}

/// Well-known locations, relative to the repository root.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
    fn discover() -> anyhow::Result<Self> {
        let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let root = manifest_dir
            .ancestors()
            .nth(2)
            .context("dust-builder must live in crates/ of the repository")?
            .to_path_buf();
        Ok(Self { root })
    }

    pub fn components(&self) -> PathBuf {
        self.root.join("components")
    }
    pub fn build(&self) -> PathBuf {
        self.root.join("build")
    }
    pub fn sources(&self) -> PathBuf {
        self.build().join("cache/sources")
    }
    pub fn cache(&self) -> PathBuf {
        self.build().join("cache")
    }
    pub fn outputs(&self) -> PathBuf {
        self.build().join("components")
    }
    pub fn work(&self) -> PathBuf {
        self.build().join("work")
    }
    pub fn image(&self) -> PathBuf {
        self.build().join("image")
    }
    pub fn out(&self) -> PathBuf {
        self.build().join("out")
    }
    pub fn keys(&self) -> PathBuf {
        self.build().join("keys")
    }

    /// Takes the exclusive lock on `build/`, held until the returned file is dropped: two
    /// builders would delete each other's work directories.
    fn lock(&self) -> anyhow::Result<std::fs::File> {
        std::fs::create_dir_all(self.build())?;
        let path = self.build().join(".lock");
        let file = std::fs::File::create(&path).with_context(|| path.display().to_string())?;
        match file.try_lock() {
            Ok(()) => Ok(file),
            Err(std::fs::TryLockError::WouldBlock) => {
                anyhow::bail!("another dust-builder is using {}", self.build().display())
            }
            Err(std::fs::TryLockError::Error(e)) => Err(e).context(path.display().to_string()),
        }
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let paths = Paths::discover()?;
    let _lock = match cli.command {
        Command::Plan { .. } => None,
        _ => Some(paths.lock()?),
    };

    match cli.command {
        Command::Builder => {
            podman::Builder::ensure(&paths)?;
        }
        Command::Fetch => {
            let recipes = recipe::Recipes::load()?;
            fetch::fetch_all(&paths, recipes.values())?;
        }
        Command::Build { components, force } => {
            let recipes = recipe::Recipes::load()?;
            let builder = podman::Builder::ensure(&paths)?;
            let order = recipes.build_order(&components)?;
            fetch::fetch_all(&paths, order.iter().copied())?;
            build::build_all(&paths, &builder, &order, force.then_some(components.as_slice()))?;
        }
        Command::Plan { component } => {
            let recipes = recipe::Recipes::load()?;
            let recipe = recipes
                .values()
                .find(|r| *r.name() == component)
                .with_context(|| format!("unknown component {component}"))?;
            println!("{} {}", recipe.name(), recipe.meta.version);
            print!("{}", recipe.plan);
        }
        Command::Image => {
            image::build_image(&paths)?;
        }
        Command::Run(args) => run::run(&paths, &args)?,
        Command::Test(args) => run::test(&paths, &args)?,
    }
    Ok(())
}

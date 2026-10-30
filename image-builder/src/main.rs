//! The hardened build system.
//!
//! Every component of the OS is compiled from source, from its recipe (`specs/`), by a
//! pipeline of targets (`specs/targets/`) bootstrapped from a pinned seed; the components of an
//! exported target are assembled into a dm-verity protected root filesystem, a signed unified
//! kernel image and a GPT disk, published as qcow2 together with a CycloneDX SBOM.
//!
//! ```text
//! cargo builder image          # build the standard target, write build/out/
//! cargo builder run            # boot the image in qemu (OVMF + swtpm)
//! cargo builder test           # boot it headless and check the smoke-test markers
//! ```

mod build;
mod environment;
mod exec;
mod fetch;
mod image;
mod keys;
mod oci;
mod patch;
mod pcr11;
mod pipeline;
mod podman;
mod progress;
mod recipe;
mod report;
mod rootfs;
mod run;
mod sbom;
mod seeds;
mod sha256;
mod specs;
mod targets;

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
    /// Downloads and verifies the source archives of all components.
    Fetch,
    /// Builds components (`<target>/<component>`, or `<component>` when one target lists it; all by
    /// default) and what they need.
    Build {
        components: Vec<String>,
        /// Rebuild the named components even if cached.
        #[arg(long)]
        force: bool,
        #[command(flatten)]
        options: build::Options,
    },
    /// Prints a component's environment and the steps of its build, without running anything.
    Plan { component: String },
    /// Builds a target and writes its qcow2 image and SBOM to build/out/.
    Image {
        #[command(flatten)]
        target: TargetArg,
        #[command(flatten)]
        options: build::Options,
    },
    /// Boots the image in qemu with a serial console.
    Run(run::RunArgs),
    /// Builds the image, boots it headless and waits for the smoke-test markers.
    Test(run::TestArgs),
}

/// The target an image command works on.
#[derive(Debug, Clone, clap::Args)]
pub struct TargetArg {
    /// A target of specs/targets/.
    #[arg(long = "target", default_value = "standard")]
    pub id: String,
}

/// Well-known locations, relative to the repository root.
#[derive(Debug, Clone)]
pub struct Paths {
    pub root: PathBuf,
}

impl Paths {
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
    pub fn specs(&self) -> PathBuf {
        self.root.join("specs")
    }
    pub fn targets(&self) -> PathBuf {
        self.specs().join("targets")
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
    /// Where the image of `target` is assembled.
    pub fn image(&self, target: &str) -> PathBuf {
        self.build().join("image").join(target)
    }
    pub fn out(&self) -> PathBuf {
        self.build().join("out")
    }
    /// Build logs: one per component and per environment, overwritten by each build.
    pub fn logs(&self) -> PathBuf {
        self.build().join("logs")
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
                anyhow::bail!("another image-builder is using {}", self.build().display())
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
        Command::Fetch => {
            let recipes = recipe::Recipes::load(&paths.specs())?;
            fetch::fetch_all(&paths, recipes.values())?;
        }
        Command::Build {
            components,
            force,
            options,
        } => {
            let pipeline = pipeline::Pipeline::load(&paths)?;
            let units = (components.iter())
                .map(|name| pipeline.unit(name))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let order = pipeline.order(&units)?;
            fetch::fetch_all(&paths, order.iter().map(|job| &job.recipe))?;
            let keys = pipeline.keys_environment()?;
            build::build_all(
                &paths,
                &order,
                &keys,
                if force { &units } else { &[] },
                options,
            )?;
        }
        Command::Plan { component } => {
            let pipeline = pipeline::Pipeline::load(&paths)?;
            let job = pipeline.job(&pipeline.unit(&component)?)?;
            println!("{} {}", job.unit, job.recipe.meta.version);
            println!("environment: {}", job.environment);
            print!("{}", job.recipe.plan);
        }
        Command::Image { target, options } => {
            image::build_image(&paths, &target.id, options, image::Disks::Image)?;
        }
        Command::Run(args) => run::run(&paths, &args)?,
        Command::Test(args) => run::test(&paths, &args)?,
    }
    Ok(())
}

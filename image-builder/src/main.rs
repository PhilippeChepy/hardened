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
//! cargo builder env --target t # build target t's image, print its tag (for podman run)
//! ```

mod build;
mod environment;
mod exec;
mod fetch;
mod image;
mod keys;
mod kspp;
mod oci;
mod patch;
mod paths;
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
mod smoke_api;
mod specs;
mod target_arg;
mod targets;

use clap::{Parser, Subcommand};

pub use paths::Paths;
pub use target_arg::TargetArg;

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
    /// Builds the image of a target (what its environment holds and its components) and prints
    /// its podman tag, to run commands in it.
    Env {
        #[command(flatten)]
        target: TargetArg,
        #[command(flatten)]
        options: build::Options,
    },
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
        Command::Env { target, options } => {
            let pipeline = pipeline::Pipeline::load(&paths)?;
            let environment = pipeline.image(pipeline.targets.get(&target.id)?)?;
            let order = pipeline.order(&environment.trees)?;
            fetch::fetch_all(&paths, order.iter().map(|job| &job.recipe))?;
            let keys = pipeline.keys_environment()?;
            let built = build::build_all(&paths, &order, &keys, &[], options)?;
            let image = environment::ensure(&paths, &environment, &built)?;
            println!("{}", image.tag);
        }
        Command::Image { target, options } => {
            image::build_image(&paths, &target.id, options, image::Disks::Image)?;
        }
        Command::Run(args) => run::run(&paths, &args)?,
        Command::Test(args) => run::test(&paths, &args)?,
    }
    Ok(())
}

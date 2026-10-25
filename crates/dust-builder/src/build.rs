//! Component builds (units), each in its own container of its environment's image, cached by
//! content.
//!
//! The cache key of a component covers its plan (every step it runs), its source checksums, the
//! in-tree files it builds from, its environment (whose key covers the components it holds) and
//! the keys of its dependencies, so any input change rebuilds it and everything depending on it.
//! Refactoring a recipe without changing its steps rebuilds nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::{Condvar, Mutex, PoisonError};
use std::time::Instant;

use anyhow::Context;
use sha2::Digest;
use walkdir::WalkDir;

use crate::Paths;
use crate::environment::Environment;
use crate::exec::{Executor, Places};
use crate::pipeline::Job;
use crate::podman::Image;
use crate::recipe::{Base, ContainerImage, Output, Recipe, Unit};
use crate::sha256::Sha256;

/// Bump to invalidate every cached component (e.g. when the build environment contract changes).
const CACHE_VERSION: &str = "4";

/// What a unit's build left: its tree, outputs, images and inventories.
#[derive(Debug, Clone)]
pub struct Built {
    pub unit: Unit,
    pub recipe: Recipe,
    pub key: Sha256,
    pub dir: PathBuf,
}

impl Built {
    /// The component's tree, installed at `/`.
    pub fn root(&self) -> PathBuf {
        self.dir.join("root")
    }
    /// One of the component's typed outputs.
    pub fn output(&self, output: &Output) -> anyhow::Result<PathBuf> {
        anyhow::ensure!(
            output.component() == self.recipe.name(),
            "{output} is not an output of {}",
            self.recipe.name()
        );
        Ok(self.dir.join("outputs").join(output.name()))
    }

    /// The OCI archive of one of the component's container images.
    pub fn container_image(&self, image: &ContainerImage) -> PathBuf {
        self.dir.join("images").join(format!("{}.tar", image.name))
    }
    /// Nested inventories for the SBOM (Go modules, Rust crates).
    pub fn sbom(&self) -> PathBuf {
        self.dir.join("sbom")
    }
}

/// How many components build at the same time by default. Each runs `make -j<cores>`, but small
/// ones spend most of their time in single-threaded configure scripts.
pub const PARALLEL: usize = 4;

/// How components build.
#[derive(Debug, Clone, Copy, clap::Args)]
pub struct Options {
    /// Components built at the same time.
    #[arg(long, default_value_t = PARALLEL)]
    pub parallel: usize,
    /// After a failure, keep building what does not depend on it, and report every failure.
    #[arg(long)]
    pub keep_going: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            parallel: PARALLEL,
            keep_going: false,
        }
    }
}

/// Builds `order` (dependencies first), up to `options.parallel` units at a time: each starts
/// once the units it needs are built. Units named in `force` are rebuilt even if cached. Build
/// output goes to `build/logs/<target>/<component>.log`. The missing signing keys are generated
/// first, in `keys` (an environment of no component).
pub fn build_all(
    paths: &Paths,
    order: &[&Job],
    keys: &Environment,
    force: Option<&[Unit]>,
    options: Options,
) -> anyhow::Result<BTreeMap<Unit, Built>> {
    std::fs::create_dir_all(paths.logs())?;
    let scheduler = Scheduler {
        paths,
        force,
        keep_going: options.keep_going,
        state: Mutex::new(State::default()),
        wake: Condvar::new(),
        images: Mutex::new(BTreeMap::new()),
    };
    crate::keys::ensure(paths, &scheduler.image(keys, &BTreeMap::new())?)?;
    std::thread::scope(|scope| {
        for _ in 0..options.parallel.max(1) {
            scope.spawn(|| scheduler.work(order));
        }
    });
    let mut state = scheduler.state.into_inner().unwrap_or_else(PoisonError::into_inner);
    match state.failed.len() {
        0 => Ok(state.built),
        1 => Err(state.failed.remove(0).1),
        _ => {
            let failed: Vec<String> = state.failed.iter().map(|(unit, _)| unit.to_string()).collect();
            anyhow::bail!(
                "{} components failed: {} (logs in {})",
                failed.len(),
                failed.join(", "),
                paths.logs().display()
            )
        }
    }
}

struct Scheduler<'a> {
    paths: &'a Paths,
    force: Option<&'a [Unit]>,
    keep_going: bool,
    state: Mutex<State>,
    /// Notified when a build ends.
    wake: Condvar,
    /// Environment images, built once (a build waiting for one waits for its build).
    images: Mutex<BTreeMap<Environment, Image>>,
}

#[derive(Default)]
struct State {
    built: BTreeMap<Unit, Built>,
    started: BTreeSet<Unit>,
    /// The failures: no build starts after the first unless keeping going.
    failed: Vec<(Unit, anyhow::Error)>,
    /// What failed, or was skipped as depending on a failure.
    unbuildable: BTreeSet<Unit>,
}

impl Scheduler<'_> {
    /// Builds units of `order` whose prerequisites are built, until all are started.
    fn work(&self, order: &[&Job]) {
        loop {
            let (job, built) = {
                let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
                loop {
                    if (!self.keep_going && !state.failed.is_empty()) || state.started.len() == order.len() {
                        return;
                    }
                    let skipped: Vec<Unit> = order
                        .iter()
                        .filter(|job| {
                            !state.started.contains(&job.unit)
                                && job.prerequisites().any(|u| state.unbuildable.contains(u))
                        })
                        .map(|job| job.unit.clone())
                        .collect();
                    if !skipped.is_empty() {
                        for unit in skipped {
                            eprintln!("==> {unit} skipped: it depends on a failed build");
                            state.started.insert(unit.clone());
                            state.unbuildable.insert(unit);
                        }
                        self.wake.notify_all();
                        continue;
                    }
                    let ready = order.iter().find(|job| {
                        !state.started.contains(&job.unit) && job.prerequisites().all(|u| state.built.contains_key(u))
                    });
                    if let Some(job) = ready {
                        state.started.insert(job.unit.clone());
                        break (*job, state.built.clone());
                    }
                    state = self.wake.wait(state).unwrap_or_else(PoisonError::into_inner);
                }
            };
            let result = self.build(job, &built);
            let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
            match result {
                Ok(done) => {
                    state.built.insert(job.unit.clone(), done);
                }
                Err(error) => {
                    state.unbuildable.insert(job.unit.clone());
                    state.failed.push((job.unit.clone(), error));
                }
            }
            self.wake.notify_all();
        }
    }

    fn build(&self, job: &Job, built: &BTreeMap<Unit, Built>) -> anyhow::Result<Built> {
        let (unit, recipe) = (&job.unit, &job.recipe);
        let image = self.image(&job.environment, built)?;
        let deps: Vec<&Built> = recipe.depends().into_iter().map(|d| &built[d]).collect();
        let key = cache_key(self.paths, &image, recipe, &deps)?;
        let dir = self
            .paths
            .outputs()
            .join(recipe.name())
            .join(hex::encode(key.prefix::<16>()));
        let forced = self.force.is_some_and(|units| units.contains(unit));

        let version = &recipe.meta.version;
        if dir.join(".complete").exists() && !forced {
            eprintln!("==> {unit} {version} (cached)");
        } else {
            eprintln!("==> building {unit} {version}");
            let started = Instant::now();
            let log_path = self
                .paths
                .logs()
                .join(unit.target.as_str())
                .join(format!("{}.log", unit.component));
            std::fs::create_dir_all(log_path.parent().context("log directory")?)?;
            let log = std::fs::File::create(&log_path)?;
            if let Err(error) = run_build(self.paths, &image, job, &deps, &dir, &log) {
                eprintln!("==> {unit} failed; the end of {}:", log_path.display());
                eprint!("{}", tail(&log_path, 40));
                return Err(error.context(format!("building {unit} (log: {})", log_path.display())));
            }
            eprintln!("==> built {unit} {version} in {:.0?}", started.elapsed());
        }
        Ok(Built {
            unit: unit.clone(),
            recipe: recipe.clone(),
            key,
            dir,
        })
    }

    /// The image of `environment`, built the first time (`built` holds its components).
    fn image(&self, environment: &Environment, built: &BTreeMap<Unit, Built>) -> anyhow::Result<Image> {
        let mut images = self.images.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(image) = images.get(environment) {
            return Ok(image.clone());
        }
        let image = crate::environment::ensure(self.paths, environment, built)?;
        images.insert(environment.clone(), image.clone());
        Ok(image)
    }
}

/// The last `lines` lines of the file at `path`.
fn tail(path: &Path, lines: usize) -> String {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let all: Vec<&str> = text.lines().collect();
    let mut out = all[all.len().saturating_sub(lines)..].join("\n");
    out.push('\n');
    out
}

fn run_build(
    paths: &Paths,
    image: &Image,
    job: &Job,
    deps: &[&Built],
    dir: &Path,
    log: &std::fs::File,
) -> anyhow::Result<()> {
    let (unit, recipe) = (&job.unit, &job.recipe);
    // Per unit: two targets may build the same component (in the same environment: to the same
    // directory) at the same time.
    let staging = dir.with_extension(format!("{}.tmp", unit.target));
    let work = paths.work().join(unit.target.as_str()).join(unit.component.as_str());
    for d in [&staging, &work] {
        if d.exists() {
            std::fs::remove_dir_all(d)?;
        }
    }
    for sub in ["root", "images", "outputs", "sbom"] {
        std::fs::create_dir_all(staging.join(sub))?;
    }
    std::fs::create_dir_all(&work)?;
    let cache = paths
        .cache()
        .join("shared")
        .join(unit.target.as_str())
        .join(unit.component.as_str());
    let registry = paths.cache().join("cargo-registry");
    std::fs::create_dir_all(&cache)?;
    std::fs::create_dir_all(&registry)?;

    let mut places = vec![
        (Base::Work, work.clone(), "/work".to_owned()),
        (Base::Repo, paths.root.clone(), "/src".to_owned()),
        (Base::Sources, paths.sources(), "/sources".to_owned()),
        (Base::Root, staging.join("root"), "/out/root".to_owned()),
        (Base::Outputs, staging.join("outputs"), "/out/outputs".to_owned()),
        (Base::Sbom, staging.join("sbom"), "/out/sbom".to_owned()),
        (Base::Cache, cache.clone(), "/cache".to_owned()),
        (Base::Secrets, paths.keys(), "/secrets".to_owned()),
    ];
    for image in recipe.images() {
        let guest = format!("/out/images/{}", image.name);
        places.push((
            Base::Image(image.name.clone()),
            staging.join("images").join(image.name.as_str()),
            guest,
        ));
    }
    for dep in deps {
        let guest = format!("/deps/{}", dep.unit);
        places.push((Base::Dep(dep.unit.clone()), dep.dir.clone(), guest));
    }
    let places = Places::new(places);

    let container = |network: bool| {
        let mut c = image
            .container("")
            .mount_ro(paths.sources(), "/sources")
            .mount_ro(&paths.root, "/src")
            .mount(&work, "/work")
            .mount(&staging, "/out")
            .mount(&cache, "/cache")
            .mount(&registry, "/usr/local/cargo/registry")
            // Per build: Go reuses cached cgo results even when the pkg-config environment
            // changes, which would leak one build's outputs into another.
            .env("GOCACHE", "/work/.go-build")
            .env("CARGO_HOME", "/usr/local/cargo")
            .env("SOURCE_DATE_EPOCH", crate::SOURCE_DATE_EPOCH.to_string())
            .network(network);
        for dep in deps {
            c = c.mount_ro(&dep.dir, format!("/deps/{}", dep.unit));
        }
        // Only the secrets the plan declares, never the whole key directory.
        for secret in &recipe.plan.secrets {
            c = c.mount_ro(paths.keys().join(secret), format!("/secrets/{secret}"));
        }
        c
    };
    let name = format!("hardened-build-{}.{}", unit.target, unit.component);
    let run = |steps, network| -> anyhow::Result<()> {
        let running = container(network).start(&name, log)?;
        Executor {
            container: &running,
            log,
            places: &places,
            jobs: jobs(),
            epoch: crate::SOURCE_DATE_EPOCH,
        }
        .run(steps)
    };
    if !recipe.plan.fetch.is_empty() {
        run(&recipe.plan.fetch, true).context("fetch phase")?;
    }
    if !recipe.plan.build.is_empty() {
        run(&recipe.plan.build, false)?;
    }

    // Container images, archived from the trees the build filled.
    for image in recipe.images() {
        let tree = staging.join("images").join(image.name.as_str());
        std::fs::create_dir_all(&tree)?;
        let archive = crate::oci::archive(&tree, image, &recipe.meta.version, crate::SOURCE_DATE_EPOCH)
            .with_context(|| format!("archiving image {}", image.name))?;
        std::fs::remove_dir_all(&tree)?;
        std::fs::write(staging.join("images").join(format!("{}.tar", image.name)), archive)?;
    }

    if dir.exists() {
        std::fs::remove_dir_all(dir)?;
    }
    std::fs::rename(&staging, dir)?;
    std::fs::write(dir.join(".complete"), b"")?;
    std::fs::remove_dir_all(&work)?;
    Ok(())
}

fn jobs() -> usize {
    std::thread::available_parallelism().map_or(4, usize::from)
}

fn cache_key(paths: &Paths, image: &Image, recipe: &Recipe, deps: &[&Built]) -> anyhow::Result<Sha256> {
    let mut hasher = sha2::Sha256::new();
    let mut field = |name: &str, value: &[u8]| {
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    };

    field("cache-version", CACHE_VERSION.as_bytes());
    field("environment", image.key.to_string().as_bytes());
    field("epoch", crate::SOURCE_DATE_EPOCH.to_string().as_bytes());
    field("version", recipe.meta.version.as_bytes());
    field("fetch", format!("{:?}", recipe.plan.fetch).as_bytes());
    field("build", format!("{:?}", recipe.plan.build).as_bytes());
    field("images", format!("{:?}", recipe.plan.images).as_bytes());
    for secret in &recipe.plan.secrets {
        let path = paths.keys().join(secret);
        let contents = std::fs::read(&path).with_context(|| path.display().to_string())?;
        field("secret", Sha256::digest(contents).to_string().as_bytes());
    }
    for source in &recipe.plan.sources {
        field("source", source.sha256.to_string().as_bytes());
    }
    for local in &recipe.local {
        let path = paths.root.join(local);
        if path.is_dir() {
            hash_tree(&paths.root, &path, &mut field)?;
        } else {
            field(
                local.as_str(),
                &std::fs::read(&path).with_context(|| path.display().to_string())?,
            );
        }
    }
    for dep in deps {
        field("dep", dep.key.to_string().as_bytes());
    }
    Ok(Sha256::finalize(hasher))
}

/// Hashes the paths and contents of the files below `dir`, in a stable order, skipping build
/// outputs (`target/`).
fn hash_tree(base: &Path, dir: &Path, field: &mut impl FnMut(&str, &[u8])) -> anyhow::Result<()> {
    let walker = WalkDir::new(dir)
        .sort_by_file_name()
        .into_iter()
        .filter_entry(|e| e.file_name() != "target");
    for entry in walker {
        let entry = entry?;
        if entry.file_type().is_file() {
            let rel = entry.path().strip_prefix(base)?.to_string_lossy().into_owned();
            field(&rel, &std::fs::read(entry.path())?);
        }
    }
    Ok(())
}

/// Where `unit` wrote `output`, among the units `built`.
pub fn locate(built: &BTreeMap<Unit, Built>, unit: &Unit, output: &Output) -> anyhow::Result<PathBuf> {
    built
        .get(unit)
        .with_context(|| format!("{output}: {unit} was not built"))?
        .output(output)
}

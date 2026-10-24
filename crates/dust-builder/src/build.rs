//! Component builds, each in its own builder container, cached by content.
//!
//! The cache key of a component covers its plan (every step it runs), its source checksums, the
//! in-tree files it builds from, the builder image and the keys of its dependencies, so any input
//! change rebuilds it and everything depending on it. Refactoring a recipe without changing its
//! steps rebuilds nothing.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Context;
use sha2::Digest;
use walkdir::WalkDir;

use crate::Paths;
use crate::exec::{Executor, Places};
use crate::podman::Builder;
use crate::recipe::{Base, ComponentName, ContainerImage, Output, Recipe};
use crate::sha256::Sha256;

/// Bump to invalidate every cached component (e.g. when the build environment contract changes).
const CACHE_VERSION: &str = "3";

/// Outputs of a built component.
#[derive(Debug, Clone)]
pub struct Built {
    pub recipe: Recipe,
    pub key: Sha256,
    pub dir: PathBuf,
}

impl Built {
    /// Files shipped in the root filesystem.
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

/// Builds `order` (dependencies first). Components named in `force` are rebuilt even if cached.
pub fn build_all(
    paths: &Paths,
    builder: &Builder,
    order: &[&Recipe],
    force: Option<&[ComponentName]>,
) -> anyhow::Result<BTreeMap<ComponentName, Built>> {
    crate::keys::ensure(paths, builder)?;
    let mut built: BTreeMap<ComponentName, Built> = BTreeMap::new();
    for recipe in order {
        // `order` lists dependencies first, so they are all built already.
        let deps: Vec<&Built> = recipe.depends().iter().map(|d| &built[d]).collect();
        let key = cache_key(paths, builder, recipe, &deps)?;
        let dir = paths
            .outputs()
            .join(recipe.name())
            .join(hex::encode(key.prefix::<16>()));
        let forced = force.is_some_and(|names| names.contains(recipe.name()));

        if dir.join(".complete").exists() && !forced {
            eprintln!("==> {} {} (cached)", recipe.name(), recipe.meta.version);
        } else {
            eprintln!("==> building {} {}", recipe.name(), recipe.meta.version);
            run_build(paths, builder, recipe, &deps, &dir)
                .with_context(|| format!("building component {}", recipe.name()))?;
        }
        built.insert(
            recipe.name().clone(),
            Built {
                recipe: (*recipe).clone(),
                key,
                dir,
            },
        );
    }
    Ok(built)
}

fn run_build(paths: &Paths, builder: &Builder, recipe: &Recipe, deps: &[&Built], dir: &Path) -> anyhow::Result<()> {
    let staging = dir.with_extension("tmp");
    let work = paths.work().join(recipe.name());
    for d in [&staging, &work] {
        if d.exists() {
            std::fs::remove_dir_all(d)?;
        }
    }
    for sub in ["root", "images", "outputs", "sbom"] {
        std::fs::create_dir_all(staging.join(sub))?;
    }
    std::fs::create_dir_all(&work)?;
    let cache = paths.cache().join("shared").join(recipe.name());
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
        let name = dep.recipe.name();
        let guest = format!("/deps/{name}/outputs");
        places.push((Base::Dep(name.clone()), dep.dir.join("outputs"), guest));
    }
    let places = Places::new(places);

    let container = |network: bool| {
        let mut c = builder
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
            .env("SOURCE_DATE_EPOCH", crate::SOURCE_DATE_EPOCH.to_string())
            .network(network);
        for dep in deps {
            c = c.mount_ro(&dep.dir, format!("/deps/{}", dep.recipe.name()));
        }
        // Only the secrets the plan declares, never the whole key directory.
        for secret in &recipe.plan.secrets {
            c = c.mount_ro(paths.keys().join(secret), format!("/secrets/{secret}"));
        }
        c
    };
    let name = format!("hardened-build-{}", recipe.name());
    let run = |steps, network| -> anyhow::Result<()> {
        let running = container(network).start(&name)?;
        Executor {
            container: &running,
            places: &places,
            jobs: jobs(),
            epoch: crate::SOURCE_DATE_EPOCH,
        }
        .run(steps)
    };
    if !recipe.plan.fetch.is_empty() {
        run(&recipe.plan.fetch, true).context("fetch phase")?;
    }
    run(&recipe.plan.build, false)?;

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

fn cache_key(paths: &Paths, builder: &Builder, recipe: &Recipe, deps: &[&Built]) -> anyhow::Result<Sha256> {
    let mut hasher = sha2::Sha256::new();
    let mut field = |name: &str, value: &[u8]| {
        hasher.update(name.as_bytes());
        hasher.update((value.len() as u64).to_le_bytes());
        hasher.update(value);
    };

    field("cache-version", CACHE_VERSION.as_bytes());
    field("builder", builder.id.to_string().as_bytes());
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

/// Where `output` was built, among the components `built`.
pub fn locate(built: &BTreeMap<ComponentName, Built>, output: &Output) -> anyhow::Result<PathBuf> {
    built
        .get(output.component())
        .with_context(|| format!("{output}: component {} was not built", output.component()))?
        .output(output)
}

//! Build environments: a root (a seed, or nothing) and the trees of components, in order (see
//! [`crate::pipeline`] for which).
//!
//! Each distinct environment is an image, built from a generated Containerfile
//! (`build/environments/<key>.Containerfile`) with the components' trees as build contexts, and
//! tagged by its key: the root's name and key, and the cache keys of its components.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context;
use sha2::Digest as _;

use crate::Paths;
use crate::build::Built;
use crate::podman::Image;
use crate::recipe::Unit;
use crate::seeds::Seed;
use crate::sha256::Sha256;

/// What an environment starts from.
#[derive(Debug, Clone)]
pub enum Root {
    /// Nothing: the environment is only components built from source.
    Scratch,
    Seed(Arc<Seed>),
}

impl Root {
    pub fn name(&self) -> &str {
        match self {
            Self::Scratch => "scratch",
            Self::Seed(seed) => seed.name.as_str(),
        }
    }
}

// Seeds are identified by their names.
impl PartialEq for Root {
    fn eq(&self, other: &Self) -> bool {
        self.name() == other.name()
    }
}

impl Eq for Root {}

impl PartialOrd for Root {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Root {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.name().cmp(other.name())
    }
}

impl std::hash::Hash for Root {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name().hash(state);
    }
}

impl std::fmt::Display for Root {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// A root and the components whose trees it holds, copied in this order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Environment {
    pub root: Root,
    pub trees: Vec<Unit>,
}

impl std::fmt::Display for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.root {
            Root::Scratch => f.write_str("an empty root")?,
            Root::Seed(seed) => write!(f, "the {} seed", seed.name)?,
        }
        if !self.trees.is_empty() {
            let trees: Vec<String> = self.trees.iter().map(ToString::to_string).collect();
            write!(f, ", with {}", trees.join(", "))?;
        }
        Ok(())
    }
}

/// The image of `environment` (its components all `built`), built if missing.
pub fn ensure(paths: &Paths, environment: &Environment, built: &BTreeMap<Unit, Built>) -> anyhow::Result<Image> {
    let root = root_image(paths, &environment.root)?;
    let mut hasher = sha2::Sha256::new();
    hasher.update(environment.root.name().as_bytes());
    if let Some(root) = &root {
        hasher.update(root.key.to_string().as_bytes());
    }
    // Build contexts are numbered: unit names may not be valid context names.
    let mut copies = Vec::new();
    for (i, unit) in environment.trees.iter().enumerate() {
        let built = built.get(unit).with_context(|| format!("{unit} is not built yet"))?;
        hasher.update(unit.to_string().as_bytes());
        hasher.update(built.key.to_string().as_bytes());
        let tree = built.root();
        if std::fs::read_dir(&tree).is_ok_and(|mut entries| entries.next().is_some()) {
            copies.push((format!("tree-{i}"), tree));
        }
    }
    let key = Sha256::finalize(hasher);
    let image = Image {
        tag: format!(
            "localhost/hardened-env-{}:{}",
            environment.root,
            hex::encode(key.prefix::<8>())
        ),
        key,
    };
    if crate::podman::exists(&image.tag)? {
        return Ok(image);
    }

    let mut containerfile = match &root {
        Some(root) => format!("FROM {}\n", root.tag),
        None => "FROM scratch\n".to_owned(),
    };
    for (context, _) in &copies {
        containerfile.push_str(&format!("COPY --from={context} / /\n"));
    }
    if root.is_none() {
        // The bootstrap toolset (static, under /cross) comes after what is built from it.
        containerfile.push_str("ENV PATH=/usr/bin:/usr/sbin:/cross/llvm/bin:/cross/bin:/cross/sbin\n");
    }
    containerfile.push_str("WORKDIR /work\n");
    let name = format!("env-{}-{}", environment.root, hex::encode(key.prefix::<8>()));
    build(paths, &name, &containerfile, &image.tag, &copies)
        .with_context(|| format!("building the environment ({environment})"))?;
    Ok(image)
}

/// The image of `root`, built from its seed's Containerfile if missing.
fn root_image(paths: &Paths, root: &Root) -> anyhow::Result<Option<Image>> {
    let Root::Seed(seed) = root else {
        return Ok(None);
    };
    let key = seed.key();
    let image = Image {
        tag: format!("localhost/hardened-root-{root}:{}", hex::encode(key.prefix::<8>())),
        key,
    };
    if !crate::podman::exists(&image.tag)? {
        eprintln!("==> building seed {root} ({})", image.tag);
        build(paths, &format!("root-{root}"), &seed.containerfile, &image.tag, &[])
            .with_context(|| format!("building seed {root}"))?;
    }
    Ok(Some(image))
}

/// Builds `containerfile` (written to `build/environments/<name>.Containerfile`) as `tag`, with
/// named build contexts.
fn build(
    paths: &Paths,
    name: &str,
    containerfile: &str,
    tag: &str,
    contexts: &[(String, PathBuf)],
) -> anyhow::Result<()> {
    let dir = paths.build().join("environments");
    std::fs::create_dir_all(&dir)?;
    let file = dir.join(format!("{name}.Containerfile"));
    std::fs::write(&file, containerfile)?;
    let log = paths.logs().join(format!("{name}.log"));
    crate::podman::build(&file, &dir, tag, contexts, &log)
}

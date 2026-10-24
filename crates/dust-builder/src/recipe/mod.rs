//! Component recipes, written in Rust: `components/<name>/recipe.rs`.
//!
//! A recipe implements [`Component`]: its [`Meta`] (for the SBOM) and `fetch`/`build` functions
//! describing its build through [`Build`]. Recipes never execute anything: the description is a
//! [`Plan`] of steps, which also records what the build uses (sources, other components'
//! outputs) and the container images it fills. The plan is what the cache key hashes.
//!
//! Component names ([`name!`]) and source checksums ([`source!`], [`crate::sha256!`]) are
//! validated at compile time; the rest of a plan when recipes load.

mod output;
mod plan;

use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component as PathComponent, Path};
use std::str::FromStr;

use anyhow::{Context, bail, ensure};
use serde::Serialize;

pub use output::Output;
pub use plan::{Arg, Base, Build, CargoBinary, Cgo, Cmd, Command, GoBuild, Loc, Mode, Piece, Plan, Step};

use crate::sha256::Sha256;

/// The OS version: the workspace version, which dust-builder shares.
pub const WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Everything a recipe needs, for `use crate::recipe::prelude::*`.
pub mod prelude {
    pub use const_format::formatcp;

    pub use super::{
        Arg, Build, CargoBinary, Cgo, Cmd, Component, ComponentName, ComponentType, ContainerImage, GoBuild, Meta,
        Mode, Output, Source, WORKSPACE_VERSION,
    };
    pub use crate::{name, source};
}

/// A component name: lowercase ASCII letters, digits and inner `-`. Used in output paths and
/// container mount points, so it can never contain `/` or `..`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(into = "String")]
pub struct ComponentName(Cow<'static, str>);

#[derive(Debug, thiserror::Error)]
#[error("invalid component name {0:?}: use lowercase ASCII letters, digits and '-'")]
pub struct InvalidComponentName(String);

/// A component name literal, validated at compile time: `name!("kernel")`.
#[macro_export]
macro_rules! name {
    ($name:literal) => {
        const { $crate::recipe::ComponentName::from_static($name) }
    };
}

impl ComponentName {
    const fn is_valid(name: &[u8]) -> bool {
        if name.is_empty() || name[0] == b'-' || name[name.len() - 1] == b'-' {
            return false;
        }
        let mut i = 0;
        while i < name.len() {
            let b = name[i];
            if !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-') {
                return false;
            }
            i += 1;
        }
        true
    }

    /// For literals; panics (a compile error in a const context) on an invalid name.
    pub const fn from_static(name: &'static str) -> Self {
        assert!(Self::is_valid(name.as_bytes()), "invalid component name");
        Self(Cow::Borrowed(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl FromStr for ComponentName {
    type Err = InvalidComponentName;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        if Self::is_valid(name.as_bytes()) {
            Ok(Self(Cow::Owned(name.to_owned())))
        } else {
            Err(InvalidComponentName(name.to_owned()))
        }
    }
}

impl From<ComponentName> for String {
    fn from(name: ComponentName) -> Self {
        name.0.into_owned()
    }
}

impl Borrow<str> for ComponentName {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<Path> for ComponentName {
    fn as_ref(&self) -> &Path {
        self.as_str().as_ref()
    }
}

impl fmt::Display for ComponentName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// CycloneDX 1.6 component type (the subset hardened's components use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ComponentType {
    Application,
    Library,
    OperatingSystem,
    Firmware,
}

/// What the SBOM says about a component.
#[derive(Debug, Clone)]
pub struct Meta {
    pub name: ComponentName,
    pub version: String,
    pub kind: ComponentType,
    pub summary: &'static str,
    /// SPDX license expression.
    pub license: &'static str,
    pub homepage: &'static str,
    /// Package URL; `pkg:generic/<name>@<version>` unless set with [`Meta::purl`].
    pub purl: String,
    pub cpe: Option<String>,
}

impl Meta {
    pub fn new(
        name: ComponentName,
        version: impl Into<String>,
        kind: ComponentType,
        summary: &'static str,
        license: &'static str,
        homepage: &'static str,
    ) -> Self {
        let version = version.into();
        Self {
            purl: format!("pkg:generic/{name}@{version}"),
            name,
            version,
            kind,
            summary,
            license,
            homepage,
            cpe: None,
        }
    }

    pub fn purl(mut self, purl: impl Into<String>) -> Self {
        self.purl = purl.into();
        self
    }

    pub fn cpe(mut self, cpe: impl Into<String>) -> Self {
        self.cpe = Some(cpe.into());
        self
    }
}

/// A pinned source archive. Declared as a constant with [`source!`]; recorded (to be fetched,
/// verified and listed in the SBOM) when the build uses it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    pub url: &'static str,
    pub sha256: Sha256,
    file: Option<&'static str>,
}

/// A source: `source!(url, sha256)`, optionally `file = "name"` when the URL does not end with a
/// usable file name. The checksum is validated at compile time; URLs may be built from constants
/// with `formatcp!`.
#[macro_export]
macro_rules! source {
    ($url:expr, $sha256:literal $(,)?) => {
        $crate::recipe::Source::new($url, $crate::sha256!($sha256), None)
    };
    ($url:expr, $sha256:literal, file = $file:expr $(,)?) => {
        $crate::recipe::Source::new($url, $crate::sha256!($sha256), Some($file))
    };
}

impl Source {
    pub const fn new(url: &'static str, sha256: Sha256, file: Option<&'static str>) -> Self {
        Self { url, sha256, file }
    }

    /// File name in the source cache.
    pub fn file_name(&self) -> Result<&'static str, String> {
        let name = self
            .file
            .unwrap_or_else(|| self.url.rsplit('/').next().unwrap_or_default());
        if name.is_empty() || name == "." || name == ".." || name.contains(['/', '\0']) {
            return Err(format!("{}: no usable file name, set `file = …`", self.url));
        }
        Ok(name)
    }
}

/// A path inside the repository: relative, without `.` or `..` components.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoPath(String);

impl TryFrom<&str> for RepoPath {
    type Error = String;

    fn try_from(path: &str) -> Result<Self, Self::Error> {
        let normal = !path.is_empty()
            && Path::new(path)
                .components()
                .all(|c| matches!(c, PathComponent::Normal(_)));
        if normal {
            Ok(Self(path.to_owned()))
        } else {
            Err(format!("invalid repository path {path:?}"))
        }
    }
}

impl RepoPath {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<Path> for RepoPath {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

/// A "from scratch" container image a component produces: the files its build installs into it
/// ([`Build::container_image`]), archived by dust-builder and shipped in the root filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerImage {
    /// The image is `localhost/hardened/<name>:<component version>`.
    pub name: ComponentName,
    /// Absolute path in the image.
    pub entrypoint: &'static str,
    /// `(uid, gid)`.
    pub user: (u32, u32),
}

impl ContainerImage {
    pub fn reference(&self, version: &str) -> String {
        crate::oci::reference(self.name.as_str(), version)
    }
}

/// A component of the image. Implemented by each `components/<name>/recipe.rs`.
pub trait Component: Sync {
    fn meta(&self) -> Meta;

    /// Repository paths an in-tree component is built from, mounted at `/src` and hashed into
    /// the cache key.
    fn local(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Steps run with network access before the build, for lockfile-verified downloads only.
    fn fetch(&self, _: &mut Build) -> anyhow::Result<()> {
        Ok(())
    }

    /// The build, run without network access.
    fn build(&self, b: &mut Build) -> anyhow::Result<()>;
}

/// A component resolved at load time: its metadata and plan.
#[derive(Clone)]
pub struct Recipe {
    pub meta: Meta,
    pub local: Vec<RepoPath>,
    pub plan: Plan,
}

impl fmt::Debug for Recipe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Recipe")
            .field("name", &self.meta.name)
            .finish_non_exhaustive()
    }
}

impl Recipe {
    pub fn name(&self) -> &ComponentName {
        &self.meta.name
    }

    /// The components whose outputs the build uses.
    pub fn depends(&self) -> &BTreeSet<ComponentName> {
        &self.plan.inputs
    }

    /// The container images the build fills.
    pub fn images(&self) -> impl Iterator<Item = &ContainerImage> {
        self.plan.images.iter()
    }

    fn resolve(component: &dyn Component) -> anyhow::Result<Self> {
        let meta = component.meta();
        ensure!(!meta.version.is_empty(), "empty version");
        ensure!(meta.purl.starts_with("pkg:"), "purl must start with \"pkg:\"");
        let plan = Plan::describe(
            &meta.name,
            &meta.version,
            |b| component.fetch(b),
            |b| component.build(b),
        )?;
        let local = component
            .local()
            .into_iter()
            .map(|path| RepoPath::try_from(path).map_err(anyhow::Error::msg))
            .collect::<anyhow::Result<_>>()?;
        Ok(Self { meta, local, plan })
    }
}

/// Every component of the image, keyed by name. Dependencies are known and acyclic, and every
/// plan described.
#[derive(Debug)]
pub struct Recipes(BTreeMap<ComponentName, Recipe>);

impl Recipes {
    pub fn load() -> anyhow::Result<Self> {
        Self::resolve(crate::components::ALL)
    }

    fn resolve(components: &[&dyn Component]) -> anyhow::Result<Self> {
        let mut recipes = BTreeMap::new();
        for component in components {
            let recipe = Recipe::resolve(*component).with_context(|| format!("component {}", component.meta().name))?;
            if let Some(previous) = recipes.insert(recipe.name().clone(), recipe) {
                bail!("component {} is defined twice", previous.name());
            }
        }
        for recipe in recipes.values() {
            for dep in recipe.depends() {
                ensure!(
                    recipes.contains_key(dep),
                    "{} uses outputs of unknown component {dep}",
                    recipe.name()
                );
            }
        }
        let recipes = Self(recipes);
        recipes.build_order(&[])?;
        Ok(recipes)
    }

    pub fn values(&self) -> impl Iterator<Item = &Recipe> {
        self.0.values()
    }

    #[cfg(test)]
    pub fn get(&self, name: &str) -> Option<&Recipe> {
        self.0.get(name)
    }

    /// The selected components (all when empty) and their dependencies, dependencies first.
    pub fn build_order(&self, selected: &[ComponentName]) -> anyhow::Result<Vec<&Recipe>> {
        fn visit<'a>(
            name: &ComponentName,
            recipes: &'a BTreeMap<ComponentName, Recipe>,
            visiting: &mut BTreeSet<&'a ComponentName>,
            done: &mut BTreeSet<&'a ComponentName>,
            order: &mut Vec<&'a Recipe>,
        ) -> anyhow::Result<()> {
            let (name, recipe) = recipes
                .get_key_value(name)
                .with_context(|| format!("unknown component {name}"))?;
            if done.contains(name) {
                return Ok(());
            }
            if !visiting.insert(name) {
                bail!("dependency cycle through component {name}");
            }
            for dep in recipe.depends() {
                visit(dep, recipes, visiting, done, order)?;
            }
            visiting.remove(name);
            done.insert(name);
            order.push(recipe);
            Ok(())
        }

        let names: Vec<&ComponentName> = if selected.is_empty() {
            self.0.keys().collect()
        } else {
            selected.iter().collect()
        };
        let (mut visiting, mut done, mut order) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
        for name in names {
            visit(name, &self.0, &mut visiting, &mut done, &mut order)?;
        }
        Ok(order)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every recipe of the repository resolves: a misused build API fails here.
    #[test]
    fn resolves_every_component() {
        let recipes = Recipes::load().unwrap();
        let order: Vec<&str> = recipes
            .build_order(&[])
            .unwrap()
            .iter()
            .map(|r| r.name().as_str())
            .collect();
        let position = |name| order.iter().position(|n| *n == name).unwrap();
        assert!(position("libseccomp") < position("runc"));
        let dust = recipes.get("dust").unwrap();
        assert!(!dust.plan.fetch.is_empty(), "dust fetches its crates");
        assert!(recipes.get("kernel").unwrap().plan.fetch.is_empty());
        let pause = recipes.get("pause").unwrap();
        assert_eq!(pause.images().count(), 1, "pause fills its sandbox image");
    }

    #[test]
    fn validates_names() {
        for bad in ["Runc", "run_c", "-runc", "runc-", "", "../runc", "a/b"] {
            assert!(bad.parse::<ComponentName>().is_err(), "{bad:?} accepted");
        }
        assert_eq!(name!("gcc-runtime").as_str(), "gcc-runtime");
        assert_eq!("gcc-runtime".parse::<ComponentName>().unwrap(), name!("gcc-runtime"));
    }

    #[test]
    fn validates_source_file_names() {
        let digest = Sha256::digest(b"");
        assert_eq!(
            Source::new("https://x/a.tar.gz", digest, None).file_name(),
            Ok("a.tar.gz")
        );
        assert_eq!(
            Source::new("https://x/", digest, Some("b.tar")).file_name(),
            Ok("b.tar")
        );
        assert!(Source::new("https://x/", digest, None).file_name().is_err());
        assert!(Source::new("https://x/..", digest, None).file_name().is_err());
        assert!(Source::new("https://x/a", digest, Some("a/b")).file_name().is_err());
    }

    #[test]
    fn validates_repo_paths() {
        for good in ["Cargo.toml", ".cargo", "crates/dust-init"] {
            assert!(RepoPath::try_from(good).is_ok(), "{good:?} rejected");
        }
        for bad in ["", "/etc", "../x", "a/../b", "./a"] {
            assert!(RepoPath::try_from(bad).is_err(), "{bad:?} accepted");
        }
    }
}

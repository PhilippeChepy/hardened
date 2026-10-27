//! Component recipes: a target's in `specs/targets/<target>/components/`, those several targets
//! build in `specs/components/` ([`declarative`] describes the format).
//!
//! A recipe gives a component's [`Meta`] (for the SBOM), and its build (and fetch phase, for
//! cargo), described through [`Build`]. Recipes never execute anything: the description is a
//! [`Plan`] of steps, which also records what the build uses (sources, other components'
//! outputs) and the container images it fills. The plan is what the cache key hashes; every plan
//! is described, and checked, when recipes load.

mod build_systems;
mod declarative;
mod output;
mod plan;

use std::borrow::{Borrow, Cow};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Component as PathComponent, Path};
use std::str::FromStr;

use anyhow::{Context, ensure};
use serde::Serialize;

pub use build_systems::Configure;
pub use output::Output;
pub use plan::{Arg, Base, Build, CargoBinary, Cgo, Cmd, Command, GoBuild, Loc, Mode, Piece, Plan, Step};

use crate::sha256::Sha256;

/// The OS version: the workspace version, which dust-builder shares.
pub const WORKSPACE_VERSION: &str = env!("CARGO_PKG_VERSION");

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

impl<'de> serde::Deserialize<'de> for ComponentName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
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

/// A component of a target, which the pipeline builds: `<target>/<component>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unit {
    pub target: ComponentName,
    pub component: ComponentName,
}

impl FromStr for Unit {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        let (target, component) = text
            .split_once('/')
            .with_context(|| format!("{text:?} is not `<target>/<component>`"))?;
        Ok(Self {
            target: target.parse()?,
            component: component.parse()?,
        })
    }
}

impl fmt::Display for Unit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.target, self.component)
    }
}

/// CycloneDX 1.6 component type (the subset hardened's components use).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
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
    pub summary: String,
    /// SPDX license expression.
    pub license: String,
    pub homepage: String,
    /// Package URL; `pkg:generic/<name>@<version>` unless the recipe sets one.
    pub purl: String,
    pub cpe: Option<String>,
}

/// A pinned source file, recorded (to be fetched, verified and listed in the SBOM) when the
/// build uses it. The source cache names it by its checksum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Source {
    pub url: &'static str,
    pub sha256: Sha256,
}

impl Source {
    /// An archive, extracted for the build (`.tar.*`, `.tgz`), rather than a file used as is.
    pub fn is_archive(&self) -> bool {
        let path = self.url.split(['?', '#']).next().unwrap_or_default();
        path.contains(".tar") || path.ends_with(".tgz")
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

/// A component described at load time: its metadata and plan, the same in every target building
/// it from this recipe.
#[derive(Clone)]
pub struct Recipe {
    pub meta: Meta,
    pub local: Vec<RepoPath>,
    /// Components of the target building it, which it builds with.
    pub depends_on: Vec<String>,
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

    /// The components whose trees or outputs the build uses.
    pub fn depends(&self) -> BTreeSet<&Unit> {
        self.plan.inputs()
    }

    /// The container images the build fills.
    pub fn images(&self) -> impl Iterator<Item = &ContainerImage> {
        self.plan.images.iter()
    }

    fn describe(recipe: &declarative::Declarative) -> anyhow::Result<Self> {
        let meta = recipe.meta.clone();
        ensure!(!meta.version.is_empty(), "empty version");
        ensure!(meta.purl.starts_with("pkg:"), "purl must start with \"pkg:\"");
        let plan = Plan::describe(&meta.name, |b| recipe.fetch(b), |b| recipe.build(b))?;
        Ok(Self {
            meta,
            local: recipe.local.clone(),
            depends_on: recipe.depends_on.clone(),
            plan,
        })
    }
}

/// Every recipe, its plan described: the components', and the targets' overrides by unit.
#[derive(Debug)]
pub struct Recipes {
    components: BTreeMap<ComponentName, Recipe>,
    overrides: BTreeMap<Unit, Recipe>,
}

impl Recipes {
    /// The repository's recipes.
    pub fn load(paths: &crate::Paths) -> anyhow::Result<Self> {
        Self::resolve(declarative::load(&paths.specs())?)
    }

    fn resolve(recipes: Vec<(Option<ComponentName>, declarative::Declarative)>) -> anyhow::Result<Self> {
        let (mut components, mut overrides) = (BTreeMap::new(), BTreeMap::new());
        for (target, loaded) in recipes {
            let name = loaded.meta.name.clone();
            let recipe = Recipe::describe(&loaded).with_context(|| match &target {
                Some(target) => format!("component {name}, as target {target} overrides it"),
                None => format!("component {name}"),
            })?;
            let duplicate = match target {
                Some(target) => {
                    let unit = Unit {
                        target,
                        component: name,
                    };
                    overrides.insert(unit, recipe).is_some()
                }
                None => components.insert(name, recipe).is_some(),
            };
            ensure!(!duplicate, "a recipe is defined twice");
        }
        Ok(Self { components, overrides })
    }

    pub fn values(&self) -> impl Iterator<Item = &Recipe> {
        self.components.values().chain(self.overrides.values())
    }

    /// The recipe of `unit`: as its target overrides it, else as the nearest of the targets it
    /// `extends` does (their own components included), else the shared one.
    pub fn get(&self, unit: &Unit, extends: &[ComponentName]) -> anyhow::Result<&Recipe> {
        let overrides = std::iter::once(&unit.target).chain(extends).find_map(|target| {
            self.overrides.get(&Unit {
                target: target.clone(),
                component: unit.component.clone(),
            })
        });
        (overrides.or_else(|| self.components.get(&unit.component))).with_context(|| format!("no recipe for {unit}"))
    }

    /// The units whose targets override their recipes.
    pub fn overridden(&self) -> impl Iterator<Item = &Unit> {
        self.overrides.keys()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        let unit: Unit = "tools/perl".parse().unwrap();
        assert_eq!((unit.target.as_str(), unit.component.as_str()), ("tools", "perl"));
        assert_eq!(unit.to_string(), "tools/perl");
        for bad in ["perl", "tools/", "/perl", "tools/a/b", "Tools/perl"] {
            assert!(bad.parse::<Unit>().is_err(), "{bad:?} accepted");
        }
    }

    #[test]
    fn extended_targets_lend_their_recipes() {
        let dir = tempfile::tempdir().unwrap();
        let recipe = |version: &str| {
            format!(
                "version = \"{version}\"\nkind = \"library\"\nsummary = \"s\"\nlicense = \"MIT\"\n\
                 homepage = \"https://example.org\"\npurl = \"pkg:generic/x@{{version}}\"\n"
            )
        };
        for (path, version) in [
            ("components/shared.toml", "1"),
            ("targets/base/components/own.toml", "2"),
            ("targets/child/components/shared.toml", "3"),
        ] {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, recipe(version)).unwrap();
        }
        for target in ["base", "child"] {
            std::fs::write(dir.path().join(format!("targets/{target}/spec.toml")), "").unwrap();
        }
        let recipes = Recipes::resolve(declarative::load(dir.path()).unwrap()).unwrap();
        let version = |unit: &str, extends: &[ComponentName]| {
            let recipe = recipes.get(&unit.parse().unwrap(), extends)?;
            anyhow::Ok(recipe.meta.version.clone())
        };
        let base = [name!("base")];
        assert_eq!(version("child/own", &base).unwrap(), "2", "the extended target's own");
        assert_eq!(
            version("child/shared", &base).unwrap(),
            "3",
            "the target's override first"
        );
        assert_eq!(version("base/shared", &[]).unwrap(), "1", "the shared one last");
        assert!(version("child/own", &[]).is_err(), "only through extends");
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
    fn validates_repo_paths() {
        for good in ["Cargo.toml", ".cargo", "crates/dust-init"] {
            assert!(RepoPath::try_from(good).is_ok(), "{good:?} rejected");
        }
        for bad in ["", "/etc", "../x", "a/../b", "./a"] {
            assert!(RepoPath::try_from(bad).is_err(), "{bad:?} accepted");
        }
    }
}

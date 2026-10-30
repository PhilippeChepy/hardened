//! The recipes of the repository, their plans described.

use std::collections::BTreeMap;
use std::iter;
use std::path::Path;

use anyhow::Context;

use crate::recipe::declarative;
use crate::recipe::{ComponentName, Meta, Plan, RepoPath, Unit};

/// A component described at load time: its metadata and plan, the same in every target building
/// it from this recipe.
#[derive(Clone)]
pub struct Recipe {
    /// What the SBOM says about it.
    pub meta: Meta,
    /// The repository paths its build reads.
    pub local: Vec<RepoPath>,
    /// Components of the target building it, which it builds with.
    pub depends_on: Vec<ComponentName>,
    /// Its build, described.
    pub plan: Plan,
}

impl Recipe {
    /// The component's name.
    #[must_use]
    pub fn name(&self) -> &ComponentName {
        &self.meta.name
    }
}

/// Every recipe, its plan described: the components', and the targets' overrides by unit.
pub struct Recipes {
    components: BTreeMap<ComponentName, Recipe>,
    overrides: BTreeMap<Unit, Recipe>,
}

impl Recipes {
    /// The recipes of `specs/`.
    pub fn load(specs: &Path) -> anyhow::Result<Self> {
        let (mut components, mut overrides) = (BTreeMap::new(), BTreeMap::new());
        for (target, recipe) in declarative::load(specs)? {
            let component = recipe.name().clone();
            match target {
                Some(target) => overrides.insert(Unit { target, component }, recipe),
                None => components.insert(component, recipe),
            };
        }
        Ok(Self {
            components,
            overrides,
        })
    }

    /// Every recipe: the shared ones, then the targets' overrides.
    pub fn values(&self) -> impl Iterator<Item = &Recipe> {
        self.components.values().chain(self.overrides.values())
    }

    /// The recipe of `unit`: as its target overrides it, else as the nearest of the targets it
    /// `extends` does (their own components included), else the shared one.
    pub fn get(&self, unit: &Unit, extends: &[ComponentName]) -> anyhow::Result<&Recipe> {
        let overrides = iter::once(&unit.target).chain(extends).find_map(|target| {
            self.overrides.get(&Unit {
                target: target.clone(),
                component: unit.component.clone(),
            })
        });
        (overrides.or_else(|| self.components.get(&unit.component)))
            .with_context(|| format!("no recipe for {unit}"))
    }

    /// The units whose targets override their recipes.
    pub fn overridden(&self) -> impl Iterator<Item = &Unit> {
        self.overrides.keys()
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use crate::name;

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
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, recipe(version)).unwrap();
        }
        for target in ["base", "child"] {
            fs::write(dir.path().join(format!("targets/{target}/spec.toml")), "").unwrap();
        }
        let recipes = Recipes::load(dir.path()).unwrap();
        let version = |unit: &str, extends: &[ComponentName]| {
            let recipe = recipes.get(&unit.parse().unwrap(), extends)?;
            anyhow::Ok(recipe.meta.version.clone())
        };
        let base = [name!("base")];
        assert_eq!(
            version("child/own", &base).unwrap(),
            "2",
            "the extended target's own"
        );
        assert_eq!(
            version("child/shared", &base).unwrap(),
            "3",
            "the target's override first"
        );
        assert_eq!(
            version("base/shared", &[]).unwrap(),
            "1",
            "the shared one last"
        );
        assert!(version("child/own", &[]).is_err(), "only through extends");
    }
}

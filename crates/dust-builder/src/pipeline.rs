//! The pipeline: every component of every target (a [`Unit`]), the environment it builds in and
//! what it uses, checked when `specs/` loads.
//!
//! A unit of target T builds from the component's recipe, merged with T's override of it if any,
//! on T's environment (its seed, or the image of the target it builds on: that target's
//! environment and components, recursively), with the trees of T's components the recipe depends
//! on, and of what those depend on, dependencies first. A dependency the environment has is
//! there already. A component listed in several targets is built in each, with its own cache key
//! (the same one when the recipe and environments are the same).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use anyhow::{Context, bail, ensure};

use crate::Paths;
use crate::environment::{Environment, Root};
use crate::recipe::{Recipe, Recipes, Unit};
use crate::seeds::Seed;
use crate::targets::{Target, Targets};

/// A unit to build: its recipe and environment.
#[derive(Debug, Clone)]
pub struct Job {
    pub unit: Unit,
    pub recipe: Recipe,
    pub environment: Environment,
}

impl Job {
    /// The units built before this one: those of its environment, and those whose trees or
    /// outputs it uses.
    pub fn prerequisites(&self) -> impl Iterator<Item = &Unit> {
        let mut all = self.recipe.depends();
        all.extend(&self.environment.trees);
        all.into_iter()
    }
}

#[derive(Debug)]
pub struct Pipeline {
    pub targets: Targets,
    pub recipes: Recipes,
    jobs: BTreeMap<Unit, Job>,
    /// What each unit depends on, resolved.
    depends: BTreeMap<Unit, Vec<Unit>>,
}

impl Pipeline {
    /// The repository's pipeline: `specs/`.
    pub fn load(paths: &Paths) -> anyhow::Result<Self> {
        let targets = Targets::load(&paths.targets())?;
        let recipes = Recipes::load(paths)?;
        Self::new(targets, recipes)
    }

    fn new(targets: Targets, recipes: Recipes) -> anyhow::Result<Self> {
        let mut pipeline = Self {
            targets,
            recipes,
            jobs: BTreeMap::new(),
            depends: BTreeMap::new(),
        };
        let (mut recipes, mut depends_on) = (BTreeMap::new(), BTreeMap::new());
        for target in pipeline.targets.values() {
            let provided = pipeline.provided(target)?;
            for unit in units(target) {
                let recipe = pipeline.recipes.get(&unit, &target.extends)?.clone();
                let mut depends = Vec::new();
                for name in &recipe.depends_on {
                    if let Some(own) = target.components.iter().find(|c| c.as_str() == name) {
                        depends.push(Unit {
                            target: target.id.clone(),
                            component: own.clone(),
                        });
                    } else {
                        ensure!(
                            provided.contains(name.as_str()),
                            "{unit} depends on {name}, which neither {} nor its environment has",
                            target.id
                        );
                    }
                }
                depends_on.insert(unit.clone(), depends);
                recipes.insert(unit, recipe);
            }
        }
        pipeline.depends = depends_on;
        let mut jobs = BTreeMap::new();
        for target in pipeline.targets.values() {
            let environment = pipeline.environment(target)?;
            for unit in units(target) {
                let mut trees = environment.trees.clone();
                let direct = &pipeline.depends[&unit];
                trees.extend(
                    (pipeline.closure(direct, Some(&unit))).with_context(|| format!("what {unit} depends on"))?,
                );
                let recipe = recipes.remove(&unit).context("listed twice")?;
                let environment = Environment {
                    root: environment.root.clone(),
                    trees,
                };
                jobs.insert(
                    unit.clone(),
                    Job {
                        unit,
                        recipe,
                        environment,
                    },
                );
            }
        }
        for unit in pipeline.recipes.overridden() {
            pipeline.targets.get(unit.target.as_str())?;
            ensure!(
                jobs.contains_key(unit),
                "specs/targets/{}/components/{}.toml: target {} does not list {}",
                unit.target,
                unit.component,
                unit.target,
                unit.component
            );
        }
        for job in jobs.values() {
            for (unit, output) in &job.recipe.plan.uses {
                let producer =
                    (jobs.get(unit)).with_context(|| format!("{} uses {unit}, which is no component", job.unit))?;
                if let Some(output) = output {
                    ensure!(
                        producer.recipe.plan.outputs.contains(output),
                        "{} uses output {output} of {unit}, which {} does not write",
                        job.unit,
                        unit.component
                    );
                }
            }
        }
        pipeline.jobs = jobs;
        let all: Vec<Unit> = pipeline.jobs.keys().cloned().collect();
        pipeline.order(&all)?;
        Ok(pipeline)
    }

    /// The targets `target` builds on: its environment, that target's environment, and so on.
    fn chain<'a>(&'a self, target: &'a Target) -> anyhow::Result<Vec<&'a Target>> {
        let mut chain = Vec::new();
        let mut next = target.environment.as_ref();
        while let Some(id) = next {
            let below = self.targets.get(id.as_str())?;
            ensure!(
                below.id != target.id && !chain.iter().any(|t: &&Target| t.id == below.id),
                "target {} builds on itself",
                target.id
            );
            chain.push(below);
            next = below.environment.as_ref();
        }
        Ok(chain)
    }

    /// The names of the components `target`'s environment has.
    fn provided(&self, target: &Target) -> anyhow::Result<BTreeSet<String>> {
        Ok((self.chain(target)?.into_iter())
            .flat_map(|below| below.components.iter().map(ToString::to_string))
            .collect())
    }

    /// `units` and what they depend on, transitively, dependencies first; `of` is not among them.
    fn closure<'a>(&self, units: impl IntoIterator<Item = &'a Unit>, of: Option<&Unit>) -> anyhow::Result<Vec<Unit>> {
        fn visit(
            unit: &Unit,
            depends: &BTreeMap<Unit, Vec<Unit>>,
            of: Option<&Unit>,
            path: &mut Vec<Unit>,
            order: &mut Vec<Unit>,
        ) -> anyhow::Result<()> {
            if order.contains(unit) {
                return Ok(());
            }
            if of == Some(unit) || path.contains(unit) {
                let cycle: Vec<String> = path.iter().chain([unit]).map(ToString::to_string).collect();
                bail!("a dependency cycle: {}", cycle.join(" → "));
            }
            path.push(unit.clone());
            for dependency in depends.get(unit).into_iter().flatten() {
                visit(dependency, depends, of, path, order)?;
            }
            path.pop();
            order.push(unit.clone());
            Ok(())
        }

        let mut order = Vec::new();
        for unit in units {
            let mut path: Vec<Unit> = of.into_iter().cloned().collect();
            visit(unit, &self.depends, of, &mut path, &mut order)?;
        }
        Ok(order)
    }

    /// What `target`'s components build on: its seed, or the image of the target below (its
    /// environment's image with its components' trees, recursively). Also what its image is
    /// assembled and booted with.
    pub fn environment(&self, target: &Target) -> anyhow::Result<Environment> {
        let mut trees = Vec::new();
        for below in self.chain(target)?.into_iter().rev() {
            trees.extend(self.closure(&units(below), None)?);
        }
        let root = target.seed.clone().map_or(Root::Scratch, Root::Seed);
        Ok(Environment { root, trees })
    }

    /// The seeds of the targets.
    pub fn seeds(&self) -> impl Iterator<Item = &Arc<Seed>> {
        self.targets.values().filter_map(|target| target.seed.as_ref())
    }

    pub fn job(&self, unit: &Unit) -> anyhow::Result<&Job> {
        self.jobs.get(unit).with_context(|| format!("no component {unit}"))
    }

    /// The unit `<target>/<component>`, or `<component>` when a single target lists it.
    pub fn unit(&self, name: &str) -> anyhow::Result<Unit> {
        if name.contains('/') {
            let unit: Unit = name.parse()?;
            self.job(&unit)?;
            return Ok(unit);
        }
        let found: Vec<&Unit> = self
            .jobs
            .keys()
            .filter(|unit| unit.component.as_str() == name)
            .collect();
        match found.as_slice() {
            [unit] => Ok((*unit).clone()),
            [] => bail!("no target lists {name}"),
            _ => {
                let all: Vec<String> = found.iter().map(ToString::to_string).collect();
                bail!("{name} is in several targets: name one of {}", all.join(", "))
            }
        }
    }

    /// The units of `target`: its content.
    pub fn content(&self, target: &Target) -> Vec<Unit> {
        units(target)
    }

    /// The selected units (all when empty) and what they need, dependencies first.
    pub fn order(&self, selected: &[Unit]) -> anyhow::Result<Vec<&Job>> {
        fn visit<'a>(
            unit: &Unit,
            jobs: &'a BTreeMap<Unit, Job>,
            visiting: &mut BTreeSet<&'a Unit>,
            done: &mut BTreeSet<&'a Unit>,
            order: &mut Vec<&'a Job>,
        ) -> anyhow::Result<()> {
            let (unit, job) = jobs
                .get_key_value(unit)
                .with_context(|| format!("no component {unit}"))?;
            if done.contains(unit) {
                return Ok(());
            }
            ensure!(visiting.insert(unit), "dependency cycle through {unit}");
            for prerequisite in job.prerequisites() {
                visit(prerequisite, jobs, visiting, done, order)?;
            }
            visiting.remove(unit);
            done.insert(unit);
            order.push(job);
            Ok(())
        }

        let all: Vec<Unit>;
        let selected = if selected.is_empty() {
            all = self.jobs.keys().cloned().collect();
            &all
        } else {
            selected
        };
        let (mut visiting, mut done, mut order) = (BTreeSet::new(), BTreeSet::new(), Vec::new());
        for unit in selected {
            visit(unit, &self.jobs, &mut visiting, &mut done, &mut order)?;
        }
        Ok(order)
    }

    /// Where the signing keys are generated, before anything is built: the seed the targets
    /// start from, with its openssl.
    pub fn keys_environment(&self) -> anyhow::Result<Environment> {
        let [seed] = self.seeds().collect::<Vec<_>>()[..] else {
            bail!("the targets start from several seeds, or none: which one generates the keys?");
        };
        Ok(Environment {
            root: Root::Seed(seed.clone()),
            trees: Vec::new(),
        })
    }
}

fn units(target: &Target) -> Vec<Unit> {
    (target.components.iter())
        .map(|component| Unit {
            target: target.id.clone(),
            component: component.clone(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The repository's pipeline loads: every reference resolves, and there is no cycle.
    #[test]
    fn the_repository_pipeline_loads() {
        let pipeline = Pipeline::load(&Paths::discover().unwrap()).unwrap();
        pipeline.order(&[]).unwrap();
        pipeline.keys_environment().unwrap();
    }
}

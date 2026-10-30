//! Targets (`specs/targets/<name>.toml`, or `<name>/spec.toml` with overrides in
//! `<name>/components/`): the pipeline, from the seed to the images.
//!
//! Like the stages of a Dockerfile, a target builds on one other: its `environment` (or, for the
//! first, on its `[seed]` of pinned images). Its image is its environment's image with its own
//! components' trees: what the next target builds on, or what is exported. A component builds on
//! that image, with the trees of the target's components its recipe `depends-on` (transitively),
//! as soon as they are built. A component builds from its recipe
//! (`specs/targets/<name>/components/<component>.toml`, or a shared one of `specs/components/` that
//! file overrides):
//!
//! ```toml
//! environment = "tools"
//! components = ["base-files", "kernel", "runc", "serviced"]
//! kernel-cmdline = ["lockdown=integrity"]
//!
//! [partition]
//! esp-size-mib = 64
//! state-size-mib = 64
//!
//! [export]
//! environment = "image-tools"
//! format = "qcow2"
//! name = "hardened"
//! ```
//!
//! An exported target is assembled, and booted by `cargo builder run` and `test`, in the image of
//! its `export.environment`: a target of its own, so that the tools assembling and booting images
//! change without rebuilding what they ship.
//!
//! `extends = "<target>"` starts from another target: its components come first, `kernel-cmdline`
//! adds to its own, the other fields replace it.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::iter;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;

use crate::recipe::{ComponentName, Unit};
use crate::seeds::{self, Seed};

const MIB: u64 = 1 << 20;

/// A target, its `extends` chain applied.
#[derive(Debug, Clone)]
pub struct Target {
    /// Its file name (`standard`), which `--target` and `<target>/<component>` name.
    pub id: ComponentName,
    /// What it builds on.
    pub builds_on: BuildsOn,
    /// The targets it `extends`, nearest first: where the recipes of their components are.
    pub extends: Vec<ComponentName>,
    /// What it builds, those of the targets it extends first.
    pub components: Vec<ComponentName>,
    /// Added to the kernel command line of its image.
    pub kernel_cmdline: Vec<String>,
    /// The partitions of its image.
    pub partition: Partition,
    /// How it is exported, if it is.
    pub export: Option<Export>,
}

impl Target {
    /// The units of its components.
    #[must_use]
    pub fn units(&self) -> Vec<Unit> {
        (self.components.iter())
            .map(|component| Unit {
                target: self.id.clone(),
                component: component.clone(),
            })
            .collect()
    }
}

/// What a target builds on.
#[derive(Debug, Clone)]
pub enum BuildsOn {
    /// Its seed (the first target's, shared with the targets extending it).
    Seed(Seed),
    /// The image of another target: its `environment`.
    Environment(ComponentName),
}

impl BuildsOn {
    /// The target it builds on, if not a seed.
    #[must_use]
    pub fn environment(&self) -> Option<&ComponentName> {
        match self {
            Self::Seed(_) => None,
            Self::Environment(id) => Some(id),
        }
    }
}

/// The partitions of an exported image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    /// Size of the ESP, in bytes.
    pub esp_size: u64,
    /// Initial size of the state partition, in bytes; storage-controller grows it to the end of the
    /// disk.
    pub state_size: u64,
}

impl Default for Partition {
    fn default() -> Self {
        Self {
            esp_size: 64 * MIB,
            state_size: 64 * MIB,
        }
    }
}

/// How a target is exported as a bootable image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Export {
    /// The target whose image assembles and boots it.
    pub environment: ComponentName,
    /// The format of its disk image.
    pub format: Format,
    /// The base name of its artifacts: `<name>-<version>-x86_64.qcow2`...
    pub name: String,
}

/// The format of an exported disk image.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
    /// A compressed qcow2 image.
    Qcow2,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct File {
    extends: Option<ComponentName>,
    seed: Option<seeds::File>,
    environment: Option<ComponentName>,
    #[serde(default)]
    components: Vec<ComponentName>,
    #[serde(default)]
    kernel_cmdline: Vec<String>,
    partition: Option<PartitionFile>,
    export: Option<ExportFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct PartitionFile {
    esp_size_mib: Option<u64>,
    state_size_mib: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct ExportFile {
    environment: Option<ComponentName>,
    format: Option<Format>,
    name: Option<String>,
}

/// Every target of `specs/targets/`, by id.
#[derive(Debug)]
pub struct Targets(BTreeMap<ComponentName, Target>);

impl Targets {
    /// The targets of `dir`: `<name>.toml`, or `<name>/spec.toml` next to its overrides.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let mut files = BTreeMap::new();
        for (id, entry) in crate::specs::entries(dir)? {
            let text = fs::read_to_string(&entry.spec)
                .with_context(|| entry.spec.display().to_string())?;
            files.insert(id, text);
        }
        Self::parse(files).with_context(|| dir.display().to_string())
    }

    fn parse(files: BTreeMap<ComponentName, String>) -> anyhow::Result<Self> {
        let mut parsed = BTreeMap::new();
        for (id, text) in files {
            let file: File = toml::from_str(&text).with_context(|| format!("{id}.toml"))?;
            parsed.insert(id, file);
        }
        let mut targets = BTreeMap::new();
        for id in parsed.keys() {
            let target =
                resolve(id, &parsed, &mut Vec::new()).with_context(|| format!("target {id}"))?;
            targets.insert(id.clone(), target);
        }
        for target in targets.values() {
            if let Some(export) = &target.export {
                ensure!(
                    export.environment != target.id && targets.contains_key(&export.environment),
                    "target {}: export.environment {} is no other target",
                    target.id,
                    export.environment
                );
            }
        }
        Ok(Self(targets))
    }

    /// The target `id`.
    pub fn get(&self, id: &str) -> anyhow::Result<&Target> {
        self.0.get(id).with_context(|| {
            let known: Vec<&str> = self.0.keys().map(ComponentName::as_str).collect();
            format!("unknown target {id:?} (known: {})", known.join(", "))
        })
    }

    /// Every target, by id.
    pub fn values(&self) -> impl Iterator<Item = &Target> {
        self.0.values()
    }
}

/// The target `id`, after the targets it extends (`chain` detects cycles).
fn resolve(
    id: &ComponentName,
    files: &BTreeMap<ComponentName, File>,
    chain: &mut Vec<ComponentName>,
) -> anyhow::Result<Target> {
    ensure!(
        !chain.contains(id),
        "extends itself through {}",
        chain
            .iter()
            .map(ComponentName::as_str)
            .collect::<Vec<_>>()
            .join(" → ")
    );
    chain.push(id.clone());
    let file = files
        .get(id)
        .with_context(|| format!("unknown target {id}"))?;
    let parent = match &file.extends {
        Some(parent) => Some(resolve(parent, files, chain)?),
        None => None,
    };
    let parent = parent.as_ref();

    let seed = match &file.seed {
        Some(seed) => Some(BuildsOn::Seed(Seed::new(id.clone(), seed).context("seed")?)),
        None => parent.and_then(|p| match &p.builds_on {
            BuildsOn::Seed(_) => Some(p.builds_on.clone()),
            BuildsOn::Environment(_) => None,
        }),
    };
    let environment = (file.environment.clone().map(BuildsOn::Environment)).or_else(|| {
        parent.and_then(|p| {
            p.builds_on
                .environment()
                .cloned()
                .map(BuildsOn::Environment)
        })
    });
    let builds_on = match (seed, environment) {
        (Some(builds_on), None) | (None, Some(builds_on)) => builds_on,
        _ => bail!("a seed or an environment: what it builds on"),
    };
    ensure!(
        builds_on.environment() != Some(id),
        "in its own environment"
    );
    let extends = match parent {
        Some(p) => iter::once(p.id.clone())
            .chain(p.extends.iter().cloned())
            .collect(),
        None => Vec::new(),
    };
    let mut components = parent.map(|p| p.components.clone()).unwrap_or_default();
    components.extend(file.components.iter().cloned());
    let mut seen = BTreeSet::new();
    for component in &components {
        ensure!(seen.insert(component), "lists {component} twice");
    }
    let mut kernel_cmdline = parent.map(|p| p.kernel_cmdline.clone()).unwrap_or_default();
    for option in &file.kernel_cmdline {
        ensure!(
            !option.is_empty() && !option.contains(char::is_whitespace) && !option.contains('"'),
            "invalid kernel command line option {option:?}"
        );
        kernel_cmdline.push(option.clone());
    }
    let mib = |size: Option<u64>, what: &str| -> anyhow::Result<Option<u64>> {
        ensure!(size != Some(0), "partition.{what} is empty");
        Ok(size.map(|size| size * MIB))
    };
    let inherited = parent.map(|p| p.partition).unwrap_or_default();
    let partition = match &file.partition {
        None => inherited,
        Some(own) => Partition {
            esp_size: mib(own.esp_size_mib, "esp-size-mib")?.unwrap_or(inherited.esp_size),
            state_size: mib(own.state_size_mib, "state-size-mib")?.unwrap_or(inherited.state_size),
        },
    };
    let inherited = parent.and_then(|p| p.export.clone());
    let export = match &file.export {
        None => inherited,
        Some(own) => Some(Export {
            environment: (own.environment.clone())
                .or(inherited.as_ref().map(|e| e.environment.clone()))
                .context("no export.environment")?,
            format: (own.format.or(inherited.as_ref().map(|e| e.format)))
                .context("no export.format")?,
            name: (own.name.clone().or(inherited.map(|e| e.name))).context("no export.name")?,
        }),
    };
    ensure!(
        export.is_some() || (kernel_cmdline.is_empty() && file.partition.is_none()),
        "kernel-cmdline and partition are for exported targets"
    );
    Ok(Target {
        id: id.clone(),
        builds_on,
        extends,
        components,
        kernel_cmdline,
        partition,
        export,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The targets of `files`, and an `image-tools` target unless they have one: what exports
    /// them.
    fn parse(files: &[(&str, &str)]) -> anyhow::Result<Targets> {
        let mut all: BTreeMap<ComponentName, String> = (files.iter())
            .map(|(id, text)| (id.parse().unwrap(), (*text).to_owned()))
            .collect();
        all.entry(crate::name!("image-tools"))
            .or_insert_with(|| "environment = \"tools\"\n".to_owned());
        Targets::parse(all)
    }

    const STANDARD: &str = "environment = \"tools\"\n\
                            components = [\"kernel\", \"runc\", \"serviced\"]\n\
                            kernel-cmdline = [\"lockdown=integrity\"]\n\
                            [partition]\nesp-size-mib = 64\nstate-size-mib = 64\n\
                            [export]\nenvironment = \"image-tools\"\nformat = \"qcow2\"\n\
                            name = \"hardened\"\n";

    #[test]
    fn extends_adds_and_replaces() {
        let targets = parse(&[
            ("standard", STANDARD),
            (
                "gpu",
                "extends = \"standard\"\ncomponents = [\"nvidia\"]\nkernel-cmdline = [\"a=b\"]\n\
                 [partition]\nstate-size-mib = 128\n[export]\nname = \"hardened-gpu\"\n",
            ),
        ])
        .unwrap();
        let gpu = targets.get("gpu").unwrap();
        let names: Vec<&str> = gpu.components.iter().map(ComponentName::as_str).collect();
        assert_eq!(names, ["kernel", "runc", "serviced", "nvidia"]);
        assert_eq!(gpu.extends, [crate::name!("standard")]);
        assert_eq!(
            gpu.builds_on.environment().map(ComponentName::as_str),
            Some("tools"),
            "inherited"
        );
        assert_eq!(gpu.kernel_cmdline, ["lockdown=integrity", "a=b"]);
        assert_eq!(
            (gpu.partition.esp_size, gpu.partition.state_size),
            (64 * MIB, 128 * MIB)
        );
        let export = gpu.export.as_ref().unwrap();
        assert_eq!(
            (
                export.environment.as_str(),
                export.name.as_str(),
                export.format
            ),
            ("image-tools", "hardened-gpu", Format::Qcow2)
        );
    }

    #[test]
    fn a_seed_is_named_after_its_target() {
        let digest = "7d9bad63fafe72a3934a6efea9f742bf3a610a169bd401533a2b57c45efa2f2d";
        let targets = parse(&[
            (
                "boot",
                &format!(
                    "components = [\"x\"]\n[seed]\nbase = \"example.org/b@sha256:{digest}\"\n"
                ),
            ),
            ("again", "extends = \"boot\"\n"),
        ])
        .unwrap();
        let seed = |id: &str| match &targets.get(id).unwrap().builds_on {
            BuildsOn::Seed(seed) => seed.name.to_string(),
            BuildsOn::Environment(_) => panic!("{id} builds on an environment"),
        };
        assert_eq!(seed("boot"), "boot");
        assert_eq!(seed("again"), "boot", "inherited");
    }

    #[test]
    fn rejects_invalid_targets() {
        for (files, why) in [
            (vec![("a", "components = [\"x\"]\n")], "no environment"),
            (
                vec![("a", "environment = \"a\"\n")],
                "in its own environment",
            ),
            (
                vec![("a", "environment = [\"b\", \"c\"]\n")],
                "a single environment",
            ),
            (
                vec![("a", "[seed]\nbase = \"example.org/base:latest\"\n")],
                "unpinned seed",
            ),
            (vec![("a", "extends = \"b\"\n")], "unknown parent"),
            (
                vec![("a", "extends = \"b\"\n"), ("b", "extends = \"a\"\n")],
                "cycle",
            ),
            (
                vec![("a", &format!("{STANDARD}color = 1\n"))],
                "unknown field",
            ),
            (
                vec![("a", &STANDARD.replace("lockdown=integrity", "a b"))],
                "option with a space",
            ),
            (
                vec![("a", &STANDARD.replace("\"serviced\"]", "\"kernel\"]"))],
                "a component twice",
            ),
            (
                vec![(
                    "a",
                    &STANDARD.replace("esp-size-mib = 64", "esp-size-mib = 0"),
                )],
                "empty ESP",
            ),
            (
                vec![("a", "environment = \"t\"\nkernel-cmdline = [\"x\"]\n")],
                "cmdline without export",
            ),
            (
                vec![("a", &STANDARD.replace("image-tools", "nope"))],
                "unknown export environment",
            ),
            (vec![("image-tools", STANDARD)], "exported by itself"),
            (
                vec![(
                    "a",
                    &STANDARD.replace("environment = \"image-tools\"\n", ""),
                )],
                "no export environment",
            ),
        ] {
            assert!(parse(&files).is_err(), "{why}");
        }
    }
}

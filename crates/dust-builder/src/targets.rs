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
//! components = ["base-files", "kernel", "runc", "dust"]
//! kernel-cmdline = ["lockdown=integrity"]
//!
//! [partition]
//! esp-size-mib = 64
//! state-size-mib = 64
//!
//! [export]
//! format = "qcow2"
//! name = "hardened"
//! ```
//!
//! An exported target is assembled, and booted by `cargo builder run` and `test`, with the tools of
//! its environment.
//!
//! `extends = "<target>"` starts from another target: its components come first, `kernel-cmdline`
//! adds to its own, the other fields replace it.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, bail, ensure};
use serde::Deserialize;

use crate::recipe::ComponentName;
use crate::seeds::{self, Seed};

const MIB: u64 = 1 << 20;

/// A target, its `extends` chain applied.
#[derive(Debug, Clone)]
pub struct Target {
    /// Its file name (`standard`), which `--target` and `<target>/<component>` name.
    pub id: ComponentName,
    /// The root it builds on (the first target), if not an empty one.
    pub seed: Option<Arc<Seed>>,
    /// The target whose image it builds on.
    pub environment: Option<ComponentName>,
    pub components: Vec<ComponentName>,
    /// Added to the kernel command line of its image.
    pub kernel_cmdline: Vec<String>,
    pub partition: Partition,
    pub export: Option<Export>,
}

/// The partitions of an exported image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Partition {
    pub esp_size: u64,
    /// Initial size of the state partition; dust-init grows it to the end of the disk.
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
    pub format: Format,
    /// The base name of its artifacts: `<name>-<version>-x86_64.qcow2`...
    pub name: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Format {
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
            let text = std::fs::read_to_string(&entry.spec).with_context(|| entry.spec.display().to_string())?;
            files.insert(id.to_string(), text);
        }
        Self::parse(&files).with_context(|| dir.display().to_string())
    }

    fn parse(files: &BTreeMap<String, String>) -> anyhow::Result<Self> {
        let mut parsed = BTreeMap::new();
        for (id, text) in files {
            let id: ComponentName = id.parse().with_context(|| format!("target {id:?}"))?;
            let file: File = toml::from_str(text).with_context(|| format!("{id}.toml"))?;
            parsed.insert(id, file);
        }
        let mut targets = BTreeMap::new();
        for id in parsed.keys() {
            let target = resolve(id, &parsed, &mut Vec::new()).with_context(|| format!("target {id}"))?;
            targets.insert(id.clone(), target);
        }
        Ok(Self(targets))
    }

    pub fn get(&self, id: &str) -> anyhow::Result<&Target> {
        self.0.get(id).with_context(|| {
            let known: Vec<&str> = self.0.keys().map(ComponentName::as_str).collect();
            format!("unknown target {id:?} (known: {})", known.join(", "))
        })
    }

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
        chain.iter().map(ComponentName::as_str).collect::<Vec<_>>().join(" → ")
    );
    chain.push(id.clone());
    let file = files.get(id).with_context(|| format!("unknown target {id}"))?;
    let parent = match &file.extends {
        Some(parent) => Some(resolve(parent, files, chain)?),
        None => None,
    };
    let parent = parent.as_ref();

    let seed = match &file.seed {
        Some(seed) => Some(Arc::new(Seed::new(id.clone(), seed).context("seed")?)),
        None => parent.and_then(|p| p.seed.clone()),
    };
    let environment = (file.environment.clone()).or_else(|| parent.and_then(|p| p.environment.clone()));
    ensure!(
        seed.is_some() != environment.is_some(),
        "a seed or an environment: what it builds on"
    );
    ensure!(environment.as_ref() != Some(id), "in its own environment");
    let mut components = parent.map(|p| p.components.clone()).unwrap_or_default();
    components.extend(file.components.iter().cloned());
    let mut seen = std::collections::BTreeSet::new();
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
            format: inherit(own.format, inherited.as_ref().map(|e| e.format), "format")?,
            name: inherit(own.name.clone(), inherited.as_ref().map(|e| e.name.clone()), "name")?,
        }),
    };
    ensure!(
        export.is_some() || (kernel_cmdline.is_empty() && file.partition.is_none()),
        "kernel-cmdline and partition are for exported targets"
    );
    Ok(Target {
        id: id.clone(),
        seed,
        environment,
        components,
        kernel_cmdline,
        partition,
        export,
    })
}

/// A field of an export, or else of the one it extends.
fn inherit<T>(own: Option<T>, parent: Option<T>, what: &str) -> anyhow::Result<T> {
    match own.or(parent) {
        Some(value) => Ok(value),
        None => bail!("no export.{what}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(files: &[(&str, &str)]) -> anyhow::Result<Targets> {
        Targets::parse(
            &files
                .iter()
                .map(|(id, text)| ((*id).to_owned(), (*text).to_owned()))
                .collect(),
        )
    }

    const STANDARD: &str = "environment = \"tools\"\ncomponents = [\"kernel\", \"runc\", \"dust\"]\n\
                            kernel-cmdline = [\"lockdown=integrity\"]\n\
                            [partition]\nesp-size-mib = 64\nstate-size-mib = 64\n\
                            [export]\nformat = \"qcow2\"\nname = \"hardened\"\n";

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
        assert_eq!(names, ["kernel", "runc", "dust", "nvidia"]);
        assert_eq!(
            gpu.environment.as_ref().map(ComponentName::as_str),
            Some("tools"),
            "inherited"
        );
        assert_eq!(gpu.kernel_cmdline, ["lockdown=integrity", "a=b"]);
        assert_eq!(
            (gpu.partition.esp_size, gpu.partition.state_size),
            (64 * MIB, 128 * MIB)
        );
        let export = gpu.export.as_ref().unwrap();
        assert_eq!((export.name.as_str(), export.format), ("hardened-gpu", Format::Qcow2));
    }

    #[test]
    fn a_seed_is_named_after_its_target() {
        let digest = "7d9bad63fafe72a3934a6efea9f742bf3a610a169bd401533a2b57c45efa2f2d";
        let targets = parse(&[
            (
                "boot",
                &format!("components = [\"x\"]\n[seed]\nbase = \"example.org/b@sha256:{digest}\"\n"),
            ),
            ("again", "extends = \"boot\"\n"),
        ])
        .unwrap();
        let boot = targets.get("boot").unwrap();
        assert_eq!(boot.seed.as_ref().unwrap().name.as_str(), "boot");
        assert!(boot.environment.is_none());
        let again = targets.get("again").unwrap();
        assert_eq!(again.seed.as_ref().unwrap().name.as_str(), "boot", "inherited");
    }

    #[test]
    fn rejects_invalid_targets() {
        for (files, why) in [
            (vec![("a", "components = [\"x\"]\n")], "no environment"),
            (vec![("a", "environment = \"a\"\n")], "in its own environment"),
            (vec![("a", "environment = [\"b\", \"c\"]\n")], "a single environment"),
            (
                vec![("a", "[seed]\nbase = \"example.org/base:latest\"\n")],
                "unpinned seed",
            ),
            (vec![("a", "extends = \"b\"\n")], "unknown parent"),
            (vec![("a", "extends = \"b\"\n"), ("b", "extends = \"a\"\n")], "cycle"),
            (vec![("a", &format!("{STANDARD}color = 1\n"))], "unknown field"),
            (
                vec![("a", &STANDARD.replace("lockdown=integrity", "a b"))],
                "option with a space",
            ),
            (
                vec![("a", &STANDARD.replace("\"dust\"]", "\"kernel\"]"))],
                "a component twice",
            ),
            (
                vec![("a", &STANDARD.replace("esp-size-mib = 64", "esp-size-mib = 0"))],
                "empty ESP",
            ),
            (
                vec![("a", "environment = \"t\"\nkernel-cmdline = [\"x\"]\n")],
                "cmdline without export",
            ),
            (vec![("A", STANDARD)], "invalid id"),
        ] {
            assert!(parse(&files).is_err(), "{why}");
        }
    }
}

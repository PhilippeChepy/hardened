//! A recipe file as the update sees it: its literal version, its sources downloaded from a URL
//! naming `{version}`, and its `[update]` table; rewritten in place, line by line, so that its
//! layout and comments stay.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};

use crate::recipe::ComponentName;
use crate::sha256::Sha256;
use crate::update::policy::Policy;
use crate::update::template;
use crate::update::version::Version;

/// A recipe the update may move to a new version.
#[derive(Debug, Clone)]
pub struct RecipeFile {
    pub path: PathBuf,
    pub component: ComponentName,
    /// The target whose override it is, if it is one.
    pub target: Option<ComponentName>,
    pub text: String,
    /// What the update does with it.
    pub status: Status,
    pub policy: Policy,
}

/// Whether the update moves a recipe.
#[derive(Debug, Clone)]
pub enum Status {
    /// Its literal `version`, and its sources whose URL names it, by name.
    Updatable {
        version: Version,
        sources: BTreeMap<String, String>,
    },
    /// Its version is another recipe's (`{<leader>.version}`): its sources naming it move with
    /// the leader's.
    Follows {
        leader: String,
        sources: BTreeMap<String, String>,
    },
    /// Not updated, and why.
    Skipped(String),
}

impl RecipeFile {
    /// The recipe of `component` at `path`, an override of `target`'s if given.
    ///
    /// # Errors
    ///
    /// When it cannot be read or is not TOML.
    pub fn read(
        path: &Path,
        component: ComponentName,
        target: Option<ComponentName>,
    ) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| path.display().to_string())?;
        let table: toml::Table =
            toml::from_str(&text).with_context(|| path.display().to_string())?;
        let policy: Policy = match table.get("update") {
            Some(update) => update
                .clone()
                .try_into()
                .with_context(|| format!("{}: [update]", path.display()))?,
            None => Policy::default(),
        };
        let status = status(&table, &policy);
        Ok(Self {
            path: path.to_owned(),
            component,
            target,
            text,
            status,
            policy,
        })
    }

    /// Its name: `<component>`, or `<target>/<component>` for an override.
    #[must_use]
    pub fn name(&self) -> String {
        match &self.target {
            Some(target) => format!("{target}/{}", self.component),
            None => self.component.to_string(),
        }
    }

    /// Its text with `version` (a follower keeps its own) and the `checksums` of its sources,
    /// by name.
    ///
    /// # Errors
    ///
    /// When the lines to change are not where the recipe format puts them.
    pub fn rewritten(
        &self,
        version: Option<&str>,
        checksums: &BTreeMap<String, Sha256>,
    ) -> anyhow::Result<String> {
        let mut lines: Vec<String> = self.text.lines().map(str::to_owned).collect();
        if let Some(version) = version {
            let top = lines
                .iter()
                .position(|line| line.trim_start().starts_with('['))
                .unwrap_or(lines.len());
            let at = (lines[..top].iter())
                .position(|line| line.starts_with("version = \""))
                .context("no top-level `version = \"...\"` line")?;
            lines[at] = format!("version = \"{version}\"");
        }
        for (source, sha256) in checksums {
            let header = format!("[sources.{source}]");
            let start = (lines.iter().position(|line| line.trim() == header))
                .with_context(|| format!("no {header} table"))?;
            let end = (lines[start + 1..].iter())
                .position(|line| line.trim_start().starts_with('['))
                .map_or(lines.len(), |end| start + 1 + end);
            let at = (lines[start + 1..end].iter())
                .position(|line| line.starts_with("sha256 = \""))
                .with_context(|| format!("no sha256 in {header}"))?;
            lines[start + 1 + at] = format!("sha256 = \"{sha256}\"");
        }
        let mut text = lines.join("\n");
        if self.text.ends_with('\n') {
            text.push('\n');
        }
        // What was written reads back as written.
        let table: toml::Table = toml::from_str(&text).context("the rewritten recipe")?;
        if let Some(version) = version {
            ensure!(
                table.get("version").and_then(toml::Value::as_str) == Some(version),
                "the rewritten recipe does not have version {version}"
            );
        }
        Ok(text)
    }
}

/// What the update does with the recipe `table`.
fn status(table: &toml::Table, policy: &Policy) -> Status {
    if let Some(why) = &policy.manual {
        return Status::Skipped(format!("updated by hand: {why}"));
    }
    let Some(version) = table.get("version").and_then(toml::Value::as_str) else {
        return Status::Skipped("no version of its own (an override)".to_owned());
    };
    if version == "workspace" {
        return Status::Skipped("built from this repository".to_owned());
    }
    let leader = (version.strip_prefix('{'))
        .and_then(|rest| rest.strip_suffix(".version}"))
        .filter(|leader| !leader.contains(['{', '}', '.']));
    let parsed = Version::parse(version);
    if leader.is_none() && parsed.is_none() {
        let why = if version.contains('{') {
            format!("its version is another's ({version})")
        } else {
            format!("version {version:?} is not a release number")
        };
        return Status::Skipped(why);
    }
    let mut sources = BTreeMap::new();
    let mut pinned = Vec::new();
    for (name, source) in table
        .get("sources")
        .and_then(toml::Value::as_table)
        .into_iter()
        .flatten()
    {
        let Some(url) = source.get("url").and_then(toml::Value::as_str) else {
            continue;
        };
        if url.contains(template::VERSION) {
            sources.insert(name.clone(), url.to_owned());
        } else {
            pinned.push(name.clone());
        }
    }
    if sources.is_empty() {
        let why = if leader.is_some() {
            format!("its version is another's ({version})")
        } else if pinned.is_empty() {
            "no source of its own".to_owned()
        } else {
            format!("no source URL names its version ({})", pinned.join(", "))
        };
        return Status::Skipped(why);
    }
    match (leader, parsed) {
        (Some(leader), _) => Status::Follows {
            leader: leader.to_owned(),
            sources,
        },
        (None, Some(version)) => Status::Updatable { version, sources },
        (None, None) => Status::Skipped(format!("version {version:?} is not a release number")),
    }
}

/// Every recipe file of `specs/`: the shared ones, then the targets' own and overrides.
///
/// # Errors
///
/// When `specs/` cannot be read, or a recipe parsed.
pub fn all(specs: &Path) -> anyhow::Result<Vec<RecipeFile>> {
    let mut files = Vec::new();
    for (component, entry) in crate::specs::entries(&specs.join("components"))? {
        files.push(RecipeFile::read(&entry.spec, component, None)?);
    }
    for (target, entry) in crate::specs::entries(&specs.join("targets"))? {
        let Some(dir) = entry
            .dir
            .map(|dir| dir.join("components"))
            .filter(|d| d.is_dir())
        else {
            continue;
        };
        for (component, entry) in crate::specs::entries(&dir)? {
            files.push(RecipeFile::read(
                &entry.spec,
                component,
                Some(target.clone()),
            )?);
        }
    }
    if files.is_empty() {
        bail!("{}: no recipe", specs.display());
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::name;

    const RECIPE: &str = "version = \"1.3.8\"\nkind = \"library\"\n\n[update]\ntrack = \"1\"\n\n\
                          # The release.\n[sources.src]\nurl = \"https://example.org/x-{version}.tar.gz\"\n\
                          sha256 = \"8839959bfcc7a0f4c609d8e4f53f1c67ae33de23775ec35beb39ff15adf11920\"\n\n\
                          [sources.pinned]\nurl = \"https://example.org/y-2.tar.gz\"\n\
                          sha256 = \"8839959bfcc7a0f4c609d8e4f53f1c67ae33de23775ec35beb39ff15adf11920\"\n";

    fn recipe(text: &str) -> RecipeFile {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.toml");
        std::fs::write(&path, text).unwrap();
        RecipeFile::read(&path, name!("x"), None).unwrap()
    }

    #[test]
    fn version_and_templated_sources() {
        let recipe = recipe(RECIPE);
        let Status::Updatable { version, sources } = &recipe.status else {
            panic!("{:?}", recipe.status);
        };
        assert_eq!(version.as_str(), "1.3.8");
        assert_eq!(sources.keys().collect::<Vec<_>>(), ["src"]);
        assert_eq!(recipe.policy.track.as_deref(), Some("1"));
    }

    #[test]
    fn rewritten_in_place() {
        let recipe = recipe(RECIPE);
        let sha = Sha256::digest(b"new");
        let text = recipe
            .rewritten(Some("1.4.0"), &[("src".to_owned(), sha)].into())
            .unwrap();
        assert!(text.starts_with("version = \"1.4.0\"\n"), "{text}");
        assert!(text.contains(&format!("[sources.src]\nurl = \"https://example.org/x-{{version}}.tar.gz\"\nsha256 = \"{sha}\"\n")), "{text}");
        assert!(text.contains("# The release.\n"));
        assert!(
            text.contains("y-2.tar.gz\"\nsha256 = \"8839959b"),
            "the other source is left"
        );
    }

    #[test]
    fn followers() {
        let text = "version = \"{nvidia-driver.version}\"\n[sources.src]\n\
                    url = \"https://example.org/x-{version}.tar.gz\"\n\
                    sha256 = \"8839959bfcc7a0f4c609d8e4f53f1c67ae33de23775ec35beb39ff15adf11920\"\n";
        let follower = recipe(text);
        let Status::Follows { leader, sources } = &follower.status else {
            panic!("{:?}", follower.status);
        };
        assert_eq!(leader, "nvidia-driver");
        assert_eq!(sources.len(), 1);
        let sha = Sha256::digest(b"new");
        let text = follower
            .rewritten(None, &[("src".to_owned(), sha)].into())
            .unwrap();
        assert!(
            text.starts_with("version = \"{nvidia-driver.version}\"\n"),
            "{text}"
        );
        assert!(text.contains(&sha.to_string()));
    }

    #[test]
    fn skipped() {
        for (text, why) in [
            ("version = \"{llvm.version}\"\n", "another's"),
            ("version = \"workspace\"\n", "this repository"),
            (
                "version = \"1\"\n[update]\nmanual = \"pinned with kubelet\"\n",
                "by hand",
            ),
            (
                "version = \"1\"\n[sources.src]\nfrom = \"llvm\"\n",
                "no source of its own",
            ),
        ] {
            let Status::Skipped(reason) = recipe(text).status else {
                panic!("{text}");
            };
            assert!(reason.contains(why), "{text}: {reason}");
        }
    }
}

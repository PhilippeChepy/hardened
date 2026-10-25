//! The files of `specs/`, laid out like Rust modules: a component or a target is `<name>.toml`,
//! or `<name>/spec.toml` when it has a directory (a recipe's patches, a target's overrides).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};

use crate::recipe::ComponentName;

/// The spec file of a directory's module.
pub const SPEC: &str = "spec.toml";

/// A component's or a target's spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// `<name>.toml` or `<name>/spec.toml`.
    pub spec: PathBuf,
    /// `<name>/`, if it has one.
    pub dir: Option<PathBuf>,
}

/// The specs of `dir`, by name.
pub fn entries(dir: &Path) -> anyhow::Result<BTreeMap<ComponentName, Entry>> {
    let mut entries = BTreeMap::new();
    for entry in std::fs::read_dir(dir).with_context(|| dir.display().to_string())? {
        let path = entry?.path();
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let (name, spec, module) = match file_name.strip_suffix(".toml") {
            _ if path.is_dir() => (file_name, path.join(SPEC), Some(path.clone())),
            Some(name) => (name, path.clone(), None),
            None => continue,
        };
        ensure!(spec.is_file(), "{}: a directory without {SPEC}", path.display());
        let name: ComponentName = name.parse().with_context(|| path.display().to_string())?;
        let duplicate = entries.insert(name.clone(), Entry { spec, dir: module }).is_some();
        ensure!(!duplicate, "{}: both {name}.toml and {name}/{SPEC}", dir.display());
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_files_and_directories() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.toml"), "").unwrap();
        std::fs::create_dir_all(dir.path().join("b/patches")).unwrap();
        std::fs::write(dir.path().join("b/spec.toml"), "").unwrap();
        std::fs::write(dir.path().join("README"), "").unwrap();
        let entries = entries(dir.path()).unwrap();
        assert_eq!(entries["a"].spec, dir.path().join("a.toml"));
        assert_eq!(entries["a"].dir, None);
        assert_eq!(entries["b"].spec, dir.path().join("b/spec.toml"));
        assert_eq!(entries["b"].dir.as_deref(), Some(dir.path().join("b").as_path()));
    }

    #[test]
    fn rejects_ambiguous_layouts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("a")).unwrap();
        assert!(entries(dir.path()).is_err(), "a directory without spec.toml");
        std::fs::write(dir.path().join("a/spec.toml"), "").unwrap();
        std::fs::write(dir.path().join("a.toml"), "").unwrap();
        assert!(entries(dir.path()).is_err(), "both a.toml and a/spec.toml");
    }
}

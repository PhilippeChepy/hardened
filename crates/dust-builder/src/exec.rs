//! Executes plans: the steps of a component's build, in its builder container.
//!
//! Commands run in the container through `podman exec`, without a shell: arguments are passed as
//! they are. File steps run on the host, on the directories mounted in the container, where
//! patterns are resolved too. Each step is printed before it runs.

use std::collections::BTreeSet;
use std::io::{Read as _, Write as _};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail, ensure};

use crate::podman::Running;
use crate::recipe::{Arg, Base, Command, Loc, Mode, Piece, Step};

/// Where each [`Base`] is, on the host and in the container.
pub struct Places(Vec<(Base, PathBuf, String)>);

impl Places {
    pub fn new(places: Vec<(Base, PathBuf, String)>) -> Self {
        Self(places)
    }

    fn get(&self, base: &Base) -> anyhow::Result<(&Path, &str)> {
        self.0
            .iter()
            .find(|(b, ..)| b == base)
            .map(|(_, host, guest)| (host.as_path(), guest.as_str()))
            .with_context(|| format!("{base:?} is not available to this build"))
    }
}

pub struct Executor<'a> {
    pub container: &'a Running,
    /// Where each step is printed, before its output.
    pub log: &'a std::fs::File,
    pub places: &'a Places,
    pub jobs: usize,
    pub epoch: u64,
}

impl Executor<'_> {
    pub fn run(&self, steps: &[Step]) -> anyhow::Result<()> {
        for step in steps {
            writeln!(&mut &*self.log, "  {step}")?;
            self.step(step).with_context(|| format!("step `{step}`"))?;
        }
        Ok(())
    }

    fn step(&self, step: &Step) -> anyhow::Result<()> {
        match step {
            Step::Unpack { archive, into } => self.unpack(archive, into),
            Step::Mkdir(dir) => Ok(std::fs::create_dir_all(self.host(dir)?)?),
            Step::Run(command) => self.exec(command, false).map(drop),
            Step::Capture { command, into } => {
                let output = self.exec(command, true)?;
                write(&self.host(into)?, output.as_bytes(), Mode::FILE)
            }
            Step::Write { to, contents, mode } => write(&self.host(to)?, contents.as_bytes(), *mode),
            Step::Patch { tree, name, diff } => {
                crate::patch::apply(&self.host(tree)?, diff).with_context(|| format!("applying {name}"))
            }
            Step::Install { from, to, mode } => {
                let [found] = &self.matches(from)?[..] else {
                    bail!("{from} must match exactly one file");
                };
                let from = self.places.get(from.base())?.0.join(found);
                ensure!(from.is_file(), "{} is not a file", from.display());
                let to = self.host(to)?;
                create_parent(&to)?;
                std::fs::copy(&from, &to).with_context(|| format!("copying {}", from.display()))?;
                set_mode(&to, *mode)
            }
            Step::Copy { from, into } => {
                let matches = self.matches(from)?;
                ensure!(!matches.is_empty(), "{from} matches nothing");
                std::fs::create_dir_all(self.host(into)?)?;
                let (_, guest) = self.places.get(from.base())?;
                let mut argv: Vec<String> = vec!["cp".into(), "-a".into()];
                argv.extend(matches.iter().map(|m| format!("{guest}/{m}")));
                argv.push(format!("{}/", self.guest(into)?));
                self.container.exec(&argv, "/", &[], false).map(drop)
            }
            Step::Symlink { target, link } => {
                let link = self.host(link)?;
                create_parent(&link)?;
                std::os::unix::fs::symlink(target, &link).with_context(|| link.display().to_string())
            }
            Step::Remove(pattern) => {
                let (base, _) = self.places.get(pattern.base())?;
                for path in self.matches(pattern)? {
                    let path = base.join(path);
                    ensure!(!path.symlink_metadata()?.is_dir(), "{} is a directory", path.display());
                    std::fs::remove_file(&path)?;
                }
                Ok(())
            }
            Step::Strip => self.strip(),
            Step::CheckEnv(env) => {
                let root = self.host(env)?;
                for dir in ["bin", "sbin", "lib", "lib64"] {
                    let path = root.join(dir);
                    ensure!(
                        !path.symlink_metadata().is_ok_and(|m| m.is_dir()),
                        "{env}/{dir} is a directory: install under /usr (merged-/usr layout)"
                    );
                }
                Ok(())
            }
            Step::CheckKernelConfig { config, fragment } => {
                let config = std::fs::read_to_string(self.host(config)?)?;
                check_kernel_config(&config, fragment)
            }
        }
    }

    fn exec(&self, command: &Command, capture: bool) -> anyhow::Result<String> {
        let argv = std::iter::once(&command.program)
            .chain(&command.args)
            .map(|arg| self.arg(arg))
            .collect::<anyhow::Result<Vec<_>>>()?;
        let env = command
            .env
            .iter()
            .map(|(key, value)| Ok((key.clone(), self.arg(value)?)))
            .collect::<anyhow::Result<Vec<_>>>()?;
        self.container.exec(&argv, &self.guest(&command.dir)?, &env, capture)
    }

    fn arg(&self, arg: &Arg) -> anyhow::Result<String> {
        let mut text = String::new();
        for piece in arg.pieces() {
            match piece {
                Piece::Text(t) => text.push_str(t),
                Piece::Loc(loc) => text.push_str(&self.guest(loc)?),
                Piece::Jobs => text.push_str(&self.jobs.to_string()),
                Piece::Epoch => text.push_str(&self.epoch.to_string()),
            }
        }
        Ok(text)
    }

    /// Extracts in the container (for its `tar` and decompressors), then keeps the single
    /// top-level directory, if there is one.
    fn unpack(&self, archive: &Loc, into: &Loc) -> anyhow::Result<()> {
        let (work, work_guest) = self.places.get(&Base::Work)?;
        let staging = work.join(".unpack");
        if staging.exists() {
            std::fs::remove_dir_all(&staging)?;
        }
        std::fs::create_dir_all(&staging)?;
        let argv = [
            "tar".into(),
            "-xf".into(),
            self.guest(archive)?,
            "-C".into(),
            format!("{work_guest}/.unpack"),
            "--no-same-owner".into(),
        ];
        self.container.exec(&argv, "/", &[], false)?;

        let into = self.host(into)?;
        ensure!(!into.exists(), "{} already exists", into.display());
        let entries: Vec<PathBuf> = std::fs::read_dir(&staging)?
            .map(|entry| entry.map(|e| e.path()))
            .collect::<Result<_, _>>()?;
        match entries.as_slice() {
            [top] if top.is_dir() => {
                std::fs::rename(top, &into)?;
                std::fs::remove_dir(&staging)?;
            }
            _ => std::fs::rename(&staging, &into)?,
        }
        Ok(())
    }

    fn strip(&self) -> anyhow::Result<()> {
        let (root, guest) = self.places.get(&Base::Root)?;
        let mut files = Vec::new();
        for entry in walkdir::WalkDir::new(root).sort_by_file_name() {
            let entry = entry?;
            if entry.file_type().is_file() && is_elf(entry.path())? {
                let relative = entry.path().strip_prefix(root)?.to_string_lossy().into_owned();
                files.push(format!("{guest}/{relative}"));
            }
        }
        for batch in files.chunks(200) {
            let mut argv = vec![
                "strip".to_owned(),
                "--strip-debug".into(),
                "--enable-deterministic-archives".into(),
            ];
            argv.extend_from_slice(batch);
            self.container.exec(&argv, "/", &[], false)?;
        }
        Ok(())
    }

    fn host(&self, loc: &Loc) -> anyhow::Result<PathBuf> {
        ensure!(!loc.is_pattern(), "{loc} is a pattern");
        let (host, _) = self.places.get(loc.base())?;
        Ok(if loc.path().is_empty() {
            host.to_owned()
        } else {
            host.join(loc.path())
        })
    }

    fn guest(&self, loc: &Loc) -> anyhow::Result<String> {
        ensure!(!loc.is_pattern(), "{loc} is a pattern");
        let (_, guest) = self.places.get(loc.base())?;
        Ok(if loc.path().is_empty() {
            guest.to_owned()
        } else {
            format!("{guest}/{}", loc.path())
        })
    }

    /// The paths, relative to the location's base, matching it (itself, if it is no pattern
    /// and exists).
    fn matches(&self, loc: &Loc) -> anyhow::Result<Vec<String>> {
        let (base, _) = self.places.get(loc.base())?;
        let segments: Vec<&str> = loc.path().split('/').filter(|s| !s.is_empty()).collect();
        let mut found = BTreeSet::new();
        expand(base, "", &segments, &mut found)?;
        Ok(found.into_iter().collect())
    }
}

/// Adds the paths below `dir` (at `relative`) matching `segments` to `found`.
fn expand(dir: &Path, relative: &str, segments: &[&str], found: &mut BTreeSet<String>) -> anyhow::Result<()> {
    let Some((first, rest)) = segments.split_first() else {
        found.insert(relative.to_owned());
        return Ok(());
    };
    let join = |name: &str| {
        if relative.is_empty() {
            name.to_owned()
        } else {
            format!("{relative}/{name}")
        }
    };
    // The names in `dir`, sorted.
    let names = || -> anyhow::Result<Vec<String>> {
        let mut names = Vec::new();
        if dir.is_dir() {
            for entry in std::fs::read_dir(dir)? {
                names.push(entry?.file_name().to_string_lossy().into_owned());
            }
        }
        names.sort();
        Ok(names)
    };

    if *first == "**" {
        expand(dir, relative, rest, found)?;
        for name in names()? {
            let path = dir.join(&name);
            if path.symlink_metadata()?.is_dir() {
                expand(&path, &join(&name), segments, found)?;
            }
        }
    } else if first.contains(['*', '?']) {
        for name in names()? {
            if wildcard(first.as_bytes(), name.as_bytes()) {
                let path = dir.join(&name);
                if rest.is_empty() || path.is_dir() {
                    expand(&path, &join(&name), rest, found)?;
                }
            }
        }
    } else {
        let path = dir.join(first);
        if path.symlink_metadata().is_ok() && (rest.is_empty() || path.is_dir()) {
            expand(&path, &join(first), rest, found)?;
        }
    }
    Ok(())
}

/// Shell-style matching of one path segment: `*`, `?`; a leading `.` must be matched literally.
fn wildcard(pattern: &[u8], name: &[u8]) -> bool {
    fn matches(pattern: &[u8], name: &[u8]) -> bool {
        match (pattern.first(), name.first()) {
            (None, None) => true,
            (Some(b'*'), _) => matches(&pattern[1..], name) || (!name.is_empty() && matches(pattern, &name[1..])),
            (Some(b'?'), Some(_)) => matches(&pattern[1..], &name[1..]),
            (Some(p), Some(n)) if p == n => matches(&pattern[1..], &name[1..]),
            _ => false,
        }
    }
    if name.first() == Some(&b'.') && pattern.first() != Some(&b'.') {
        return false;
    }
    matches(pattern, name)
}

fn is_elf(path: &Path) -> anyhow::Result<bool> {
    let mut magic = [0; 4];
    let mut file = std::fs::File::open(path)?;
    Ok(file.read(&mut magic)? == 4 && magic == *b"\x7fELF")
}

fn create_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

fn write(path: &Path, contents: &[u8], mode: Mode) -> anyhow::Result<()> {
    create_parent(path)?;
    std::fs::write(path, contents).with_context(|| path.display().to_string())?;
    set_mode(path, mode)
}

fn set_mode(path: &Path, mode: Mode) -> anyhow::Result<()> {
    Ok(std::fs::set_permissions(
        path,
        std::fs::Permissions::from_mode(mode.bits()),
    )?)
}

/// Every `CONFIG_X=v` line of the fragment must be in the `.config`, every `CONFIG_X=n` absent.
fn check_kernel_config(config: &str, fragment: &str) -> anyhow::Result<()> {
    let applied: BTreeSet<&str> = config.lines().collect();
    let mut seen = BTreeSet::new();
    let mut problems = Vec::new();
    for (number, line) in fragment.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((symbol, value)) = line.split_once('=').filter(|(s, _)| s.starts_with("CONFIG_")) else {
            bail!("fragment line {}: expected CONFIG_<SYMBOL>=<value>", number + 1);
        };
        ensure!(
            seen.insert(symbol),
            "fragment line {}: {symbol} is set twice",
            number + 1
        );
        if value == "n" {
            let prefix = format!("{symbol}=");
            if config.lines().any(|l| l.starts_with(&prefix)) {
                problems.push(format!("{symbol} should be disabled"));
            }
        } else if !applied.contains(line) {
            problems.push(format!("{line} not applied (unmet dependencies?)"));
        }
    }
    ensure!(problems.is_empty(), "kernel config:\n  {}", problems.join("\n  "));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wildcards_match_like_the_shell() {
        assert!(wildcard(b"libseccomp.so.2*", b"libseccomp.so.2.6.1"));
        assert!(wildcard(b"lib?.so", b"liba.so"));
        assert!(!wildcard(b"*", b".hidden"));
        assert!(wildcard(b".*", b".hidden"));
        assert!(!wildcard(b"*.so", b"libx.so.1"));
    }

    #[test]
    fn patterns_expand_below_their_base() {
        let dir = tempfile::tempdir().unwrap();
        for file in ["usr/lib64/libgcc_s.so.1", "usr/lib/libx.so.1", "usr/lib/libx.a"] {
            let path = dir.path().join(file);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, b"").unwrap();
        }
        let find = |pattern: &str| {
            let segments: Vec<&str> = pattern.split('/').collect();
            let mut found = BTreeSet::new();
            expand(dir.path(), "", &segments, &mut found).unwrap();
            found.into_iter().collect::<Vec<_>>()
        };
        assert_eq!(find("**/libgcc_s.so.1"), ["usr/lib64/libgcc_s.so.1"]);
        assert_eq!(find("usr/lib/*.so.*"), ["usr/lib/libx.so.1"]);
        assert_eq!(find("usr/*"), ["usr/lib", "usr/lib64"]);
        assert!(find("usr/lib/none").is_empty());
    }

    #[test]
    fn kernel_config_misses_are_reported() {
        let config = "CONFIG_A=y\nCONFIG_B=m\n# CONFIG_C is not set\nCONFIG_E=\"x\"\n";
        assert!(check_kernel_config(config, "# c\n\nCONFIG_A=y\nCONFIG_C=n\nCONFIG_E=\"x\"\n").is_ok());
        let error = check_kernel_config(config, "CONFIG_A=m\nCONFIG_B=n\nCONFIG_D=y\n")
            .unwrap_err()
            .to_string();
        for expected in [
            "CONFIG_A=m not applied",
            "CONFIG_B should be disabled",
            "CONFIG_D=y not applied",
        ] {
            assert!(error.contains(expected), "{expected:?} missing from {error}");
        }
        assert!(check_kernel_config(config, "CONFIG_A=y\nCONFIG_A=n\n").is_err());
        assert!(check_kernel_config(config, "A=y\n").is_err());
    }
}

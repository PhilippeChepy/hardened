//! `cargo builder update`: finds the recipes' new releases, downloads and checks their sources,
//! rewrites the recipes' versions and checksums, then builds what changed and what depends on
//! it, putting back each recipe whose update breaks a build. What remains for the operator is
//! the audit of the new sources, and the report's list of places to look at.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use anyhow::Context;

use crate::Paths;
use crate::build;
use crate::fetch;
use crate::pipeline::Pipeline;
use crate::recipe::Unit;
use crate::sha256::Sha256;
use crate::update::http;
use crate::update::probe::{Found, Probe};
use crate::update::recipe_file::{self, RecipeFile, Status};
use crate::update::template;
use crate::update::verify::{self, Download, Verified};
use crate::update::version::Version;

/// What to update, and how far to go.
#[derive(Debug, Clone, clap::Args)]
pub struct Args {
    /// Recipes to update (`<component>`, or `<target>/<component>` for a target's own or
    /// override); all by default.
    pub components: Vec<String>,
    /// Only finds the new versions: downloads, rewrites and builds nothing.
    #[arg(long)]
    pub dry_run: bool,
    /// Rewrites the recipes without building them.
    #[arg(long)]
    pub no_build: bool,
    #[command(flatten)]
    pub options: build::Options,
}

/// A recipe moved to a new version, with the recipes following it.
struct Updated {
    /// The leader first, then its followers.
    files: Vec<RecipeFile>,
    from: Version,
    to: Version,
    /// How each source was checked: `<recipe> <source>`.
    verified: Vec<(String, Verified)>,
}

impl Updated {
    fn name(&self) -> String {
        self.files.first().map(RecipeFile::name).unwrap_or_default()
    }

    /// Writes back the recipes as they were.
    fn put_back(&self) -> anyhow::Result<()> {
        for file in &self.files {
            std::fs::write(&file.path, &file.text)
                .with_context(|| file.path.display().to_string())?;
        }
        Ok(())
    }
}

/// The run's findings, printed at its end.
#[derive(Default)]
struct Report {
    updated: Vec<Updated>,
    available: Vec<(String, Version, Version)>,
    current: Vec<(String, Version)>,
    refused: Vec<(String, String)>,
    reverted: Vec<(String, Version, String)>,
    skipped: Vec<(String, String)>,
    unexplained: Vec<String>,
}

/// Runs the update.
///
/// # Errors
///
/// When `specs/` cannot be read or written, or a build cannot run at all.
pub fn run(paths: &Paths, args: &Args) -> anyhow::Result<()> {
    let all = recipe_file::all(&paths.specs())?;
    // Followers move with their leaders, selected or not.
    let mut followers: BTreeMap<String, Vec<RecipeFile>> = BTreeMap::new();
    for file in &all {
        if let Status::Follows { leader, .. } = &file.status {
            followers
                .entry(leader.clone())
                .or_default()
                .push(file.clone());
        }
    }
    let files = select(all, &args.components)?;
    let keys = verify::keys_dir(&paths.specs());
    let mut report = Report::default();
    for file in files {
        let name = file.name();
        let (version, sources) = match &file.status {
            Status::Updatable { version, sources } => (version.clone(), sources.clone()),
            Status::Follows { leader, .. } => {
                report.skipped.push((name, format!("moves with {leader}")));
                continue;
            }
            Status::Skipped(why) => {
                report.skipped.push((name, why.clone()));
                continue;
            }
        };
        eprintln!("==> {name} {version}");
        let (newer, found) = match newest(&file, &version, &sources) {
            Ok(Some(found)) => found,
            Ok(None) => {
                report.current.push((name, version));
                continue;
            }
            Err(e) => {
                report.refused.push((name, format!("{e:#}")));
                continue;
            }
        };
        if args.dry_run {
            report.available.push((name, version, newer));
            continue;
        }
        let group = (followers.get(file.component.as_str()).cloned()).unwrap_or_default();
        match update_group(paths, &keys, file, group, &sources, &newer, &found) {
            Ok((files, texts, verified)) => {
                for (file, text) in files.iter().zip(&texts) {
                    std::fs::write(&file.path, text)
                        .with_context(|| file.path.display().to_string())?;
                }
                eprintln!("==> {name}: {version} -> {newer}");
                report.updated.push(Updated {
                    files,
                    from: version,
                    to: newer,
                    verified,
                });
            }
            Err(e) => report.refused.push((name, format!("{newer}: {e:#}"))),
        }
    }
    if !args.dry_run && !args.no_build && !report.updated.is_empty() {
        build_and_revert(paths, args.options, &mut report)?;
    }
    print!("{}", render(paths, &report));
    Ok(())
}

/// The recipes `names` select (all without names).
fn select(files: Vec<RecipeFile>, names: &[String]) -> anyhow::Result<Vec<RecipeFile>> {
    if names.is_empty() {
        return Ok(files);
    }
    for name in names {
        anyhow::ensure!(
            (files.iter()).any(|f| f.name() == *name || f.component.as_str() == name),
            "no recipe {name}"
        );
    }
    Ok(files
        .into_iter()
        .filter(|f| {
            names
                .iter()
                .any(|n| f.name() == *n || f.component.as_str() == n)
        })
        .collect())
}

/// The newest release of `file` after `version`, within its track, and what its probe found.
fn newest(
    file: &RecipeFile,
    version: &Version,
    sources: &BTreeMap<String, String>,
) -> anyhow::Result<Option<(Version, Found)>> {
    // The main source names the releases: `src`, else the first.
    let url = (sources.get("src"))
        .or_else(|| sources.values().next())
        .context("no source")?;
    let probe = Probe::infer(url, &file.policy).with_context(|| {
        format!("nothing lists the releases of {url}: give [update] a repository or a listing")
    })?;
    let track = match &file.policy.track {
        Some(track) => Some(
            Version::parse(track)
                .with_context(|| format!("[update] track {track:?} is not a version"))?,
        ),
        None => None,
    };
    let found = probe.probe().with_context(|| probe.to_string())?;
    let newest = (found.versions.iter())
        .filter(|v| v.same_scheme(version) && *v > version)
        .filter(|v| track.as_ref().is_none_or(|track| v.in_track(track)))
        .max()
        .cloned();
    Ok(newest.map(|newest| (newest, found)))
}

/// Moves `leader` and its `followers` to `version`: their new texts, and how each source was
/// checked. One failure moves none.
#[expect(
    clippy::type_complexity,
    reason = "the group's files, texts and checks, in order"
)]
fn update_group(
    paths: &Paths,
    keys: &Path,
    leader: RecipeFile,
    followers: Vec<RecipeFile>,
    sources: &BTreeMap<String, String>,
    version: &Version,
    found: &Found,
) -> anyhow::Result<(Vec<RecipeFile>, Vec<String>, Vec<(String, Verified)>)> {
    let mut texts = Vec::new();
    let mut verified = Vec::new();
    let (checksums, checks) = fetch_sources(paths, keys, &leader, sources, version, found)?;
    texts.push(leader.rewritten(Some(version.as_str()), &checksums)?);
    verified.extend(
        checks
            .into_iter()
            .map(|(s, v)| (format!("{} {s}", leader.name()), v)),
    );
    for follower in &followers {
        let Status::Follows { sources, .. } = &follower.status else {
            continue;
        };
        let (checksums, checks) =
            fetch_sources(paths, keys, follower, sources, version, &Found::default())
                .with_context(|| follower.name())?;
        texts.push(follower.rewritten(None, &checksums)?);
        verified.extend(
            checks
                .into_iter()
                .map(|(s, v)| (format!("{} {s}", follower.name()), v)),
        );
    }
    let mut files = vec![leader];
    files.extend(followers);
    Ok((files, texts, verified))
}

/// Downloads and checks each of `sources` (of `file`) at `version`: their checksums, and how each
/// was checked.
#[expect(clippy::type_complexity, reason = "checksums and checks, by source")]
fn fetch_sources(
    paths: &Paths,
    keys: &Path,
    file: &RecipeFile,
    sources: &BTreeMap<String, String>,
    version: &Version,
    found: &Found,
) -> anyhow::Result<(BTreeMap<String, Sha256>, Vec<(String, Verified)>)> {
    let dir = paths.sources();
    std::fs::create_dir_all(&dir)?;
    let mut checksums = BTreeMap::new();
    let mut verified = Vec::new();
    for (name, url) in sources {
        let url = template::substitute(url, version.as_str());
        eprintln!("==> fetching {url}");
        let partial = dir.join(format!("update-{}.part", file.component));
        let sha256 = http::download(&url, &partial)?;
        let file_name = url.rsplit('/').next().unwrap_or_default().to_owned();
        let download = Download {
            url: &url,
            path: &partial,
            sha256,
            indexed: found
                .checksums
                .get(&(version.as_str().to_owned(), file_name))
                .copied(),
        };
        let checked = verify::verify(&download, &file.policy, keys);
        let checked = match checked {
            Ok(checked) => checked,
            Err(e) => {
                let _ = std::fs::remove_file(&partial);
                return Err(e);
            }
        };
        // The source cache names files by checksum: the build finds it there.
        std::fs::rename(&partial, dir.join(sha256.to_string()))?;
        checksums.insert(name.clone(), sha256);
        verified.push((name.clone(), checked));
    }
    Ok((checksums, verified))
}

/// Builds the updated recipes' units and those depending on them, putting back the recipes a
/// failure is due to, until what remains builds.
fn build_and_revert(
    paths: &Paths,
    options: build::Options,
    report: &mut Report,
) -> anyhow::Result<()> {
    let options = build::Options {
        keep_going: true,
        ..options
    };
    loop {
        if report.updated.is_empty() {
            return Ok(());
        }
        let pipeline = Pipeline::load(paths)?;
        let all: Vec<Unit> = (pipeline.targets.values())
            .flat_map(|target| target.units())
            .collect();
        let mut closures = BTreeMap::new();
        for unit in &all {
            closure(&pipeline, unit, &mut closures)?;
        }
        // Each updated recipe's units: those of its component (a superset for overrides: the
        // others are unchanged, hence cached).
        let units_of = |updated: &Updated| -> BTreeSet<Unit> {
            (all.iter())
                .filter(|unit| updated.files.iter().any(|f| unit.component == f.component))
                .cloned()
                .collect()
        };
        let updated_units: BTreeSet<Unit> = report.updated.iter().flat_map(units_of).collect();
        let selected: Vec<Unit> = (all.iter())
            .filter(|unit| {
                updated_units.contains(*unit)
                    || closures[*unit].iter().any(|u| updated_units.contains(u))
            })
            .cloned()
            .collect();
        let order = pipeline.order(&selected)?;
        fetch::fetch_all(paths, order.iter().map(|job| &job.recipe))?;
        let keys = pipeline.keys_environment()?;
        let outcome = build::build_each(paths, &order, &keys, &[], options)?;
        if outcome.failed.is_empty() {
            return Ok(());
        }
        let mut blamed = BTreeSet::new();
        for (unit, error) in &outcome.failed {
            let own = (report.updated.iter().enumerate())
                .filter(|(_, u)| units_of(u).contains(unit))
                .map(|(i, _)| i)
                .collect::<Vec<_>>();
            let culprits = if own.is_empty() {
                (report.updated.iter().enumerate())
                    .filter(|(_, u)| units_of(u).iter().any(|own| closures[unit].contains(own)))
                    .map(|(i, _)| i)
                    .collect()
            } else {
                own
            };
            if culprits.is_empty() {
                report.unexplained.push(format!("{unit}: {error:#}"));
            }
            for i in culprits {
                if blamed.insert(i) {
                    let reason = format!("{unit} failed: {error:#}");
                    let updated = &report.updated[i];
                    updated.put_back()?;
                    eprintln!("==> {}: put back to {}", updated.name(), updated.from);
                    report
                        .reverted
                        .push((updated.name(), updated.to.clone(), reason));
                }
            }
        }
        if blamed.is_empty() {
            // Failures the updates do not explain: building again would fail the same way.
            return Ok(());
        }
        let mut index = 0;
        report.updated.retain(|_| {
            let keep = !blamed.contains(&index);
            index += 1;
            keep
        });
    }
}

/// What `unit` builds with, transitively, memoized in `closures`.
fn closure<'a>(
    pipeline: &Pipeline,
    unit: &Unit,
    closures: &'a mut BTreeMap<Unit, BTreeSet<Unit>>,
) -> anyhow::Result<&'a BTreeSet<Unit>> {
    if !closures.contains_key(unit) {
        let mut all = BTreeSet::new();
        let direct: Vec<Unit> = pipeline.job(unit)?.prerequisites().cloned().collect();
        for prerequisite in direct {
            all.extend(closure(pipeline, &prerequisite, closures)?.iter().cloned());
            all.insert(prerequisite);
        }
        closures.insert(unit.clone(), all);
    }
    Ok(&closures[unit])
}

/// The report: what changed and how it was checked, what did not, and where else the old
/// versions appear.
fn render(paths: &Paths, report: &Report) -> String {
    let mut out = String::new();
    let root = paths
        .specs()
        .parent()
        .map(Path::to_owned)
        .unwrap_or_default();
    if !report.updated.is_empty() {
        let _ = writeln!(out, "\nUpdated (audit the new sources):");
        for updated in &report.updated {
            let _ = writeln!(
                out,
                "  {} {} -> {}",
                updated.name(),
                updated.from,
                updated.to
            );
            for (source, verified) in &updated.verified {
                let _ = writeln!(out, "    {source}: {verified}");
            }
            for file in &updated.files {
                for place in elsewhere(&root, file, updated.from.as_str()) {
                    let _ = writeln!(out, "    check {place}");
                }
            }
        }
    }
    if !report.available.is_empty() {
        let _ = writeln!(out, "\nAvailable (dry run):");
        for (name, from, to) in &report.available {
            let _ = writeln!(out, "  {name} {from} -> {to}");
        }
    }
    if !report.reverted.is_empty() {
        let _ = writeln!(out, "\nPut back (their update breaks a build):");
        for (name, to, reason) in &report.reverted {
            let first = reason.lines().next().unwrap_or_default();
            let _ = writeln!(out, "  {name} {to}: {first}");
        }
    }
    if !report.unexplained.is_empty() {
        let _ = writeln!(out, "\nFailed, not because of an update:");
        for failure in &report.unexplained {
            let _ = writeln!(out, "  {}", failure.lines().next().unwrap_or_default());
        }
    }
    if !report.refused.is_empty() {
        let _ = writeln!(out, "\nNot updated (errors):");
        for (name, why) in &report.refused {
            let _ = writeln!(out, "  {name}: {why}");
        }
    }
    if !report.current.is_empty() {
        let names: Vec<String> = (report.current.iter())
            .map(|(name, version)| format!("{name} {version}"))
            .collect();
        let _ = writeln!(out, "\nUp to date: {}", names.join(", "));
    }
    if !report.skipped.is_empty() {
        let _ = writeln!(out, "\nSkipped:");
        for (name, why) in &report.skipped {
            let _ = writeln!(out, "  {name}: {why}");
        }
    }
    out
}

/// The lines of the repository, outside the recipe, naming `version` (and the component, for a
/// short version): version constants and documentation the update does not rewrite.
fn elsewhere(root: &Path, file: &RecipeFile, version: &str) -> Vec<String> {
    let component = file.component.as_str();
    // A version of three numbers or more names the component alone (`595.112.07`): a shorter
    // one, only on a line naming the component.
    let distinctive = version.matches('.').count() >= 2;
    let skip = ["build", "target", ".git"];
    let mut places = Vec::new();
    let walk = walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|entry| {
            let name = entry.file_name().to_string_lossy();
            !(entry.depth() == 1 && skip.contains(&name.as_ref())) && name != "target"
        });
    for entry in walk.filter_map(Result::ok) {
        let path = entry.path();
        if !entry.file_type().is_file() || path == file.path {
            continue;
        }
        if entry.metadata().is_ok_and(|m| m.len() > 1 << 20) {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        for (number, line) in text.lines().enumerate() {
            if line.contains(version) && (distinctive || line.contains(component)) {
                let relative = path.strip_prefix(root).unwrap_or(path);
                places.push(format!("{}:{}", relative.display(), number + 1));
            }
        }
    }
    places
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selected_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.toml");
        std::fs::write(&path, "version = \"1\"\n").unwrap();
        let file = RecipeFile::read(&path, crate::name!("x"), Some(crate::name!("t"))).unwrap();
        assert_eq!(
            select(vec![file.clone()], &["t/x".to_owned()])
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            select(vec![file.clone()], &["x".to_owned()]).unwrap().len(),
            1
        );
        assert!(select(vec![file], &["y".to_owned()]).is_err());
    }
}

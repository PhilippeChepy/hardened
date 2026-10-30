//! Applies unified diffs (`diff -u`, `git format-patch`) to a source tree, for [`Step::Patch`].
//!
//! Paths lose their first component (`patch -p1`). A hunk applies where its context and removed
//! lines match exactly, searched outward from the line it names (upstream files move); there is
//! no fuzz, so a patch that no longer fits fails instead of applying somewhere else. Files are
//! created from and deleted to `/dev/null`.
//!
//! [`Step::Patch`]: crate::recipe::Step::Patch

use std::path::{Component, Path, PathBuf};

use anyhow::{Context, bail, ensure};

/// One file's changes.
#[derive(Debug, PartialEq, Eq)]
struct FilePatch {
    change: Change,
    hunks: Vec<Hunk>,
}

/// What a patch does to a file.
#[derive(Debug, PartialEq, Eq)]
enum Change {
    /// From `/dev/null`.
    Create(PathBuf),
    /// To `/dev/null`.
    Delete(PathBuf),
    /// Changed, and renamed when `old` and `new` differ.
    Modify { old: PathBuf, new: PathBuf },
}

impl Change {
    fn old(&self) -> Option<&Path> {
        match self {
            Self::Create(_) => None,
            Self::Delete(old) | Self::Modify { old, .. } => Some(old),
        }
    }

    /// The file the patch leaves, or deletes.
    fn target(&self) -> &Path {
        match self {
            Self::Create(path) | Self::Delete(path) | Self::Modify { new: path, .. } => path,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Hunk {
    /// 1-based line of the old file where the hunk starts (0 for an empty file).
    old_start: usize,
    /// Context and removed lines, in order.
    old: Vec<Line>,
    /// Context and added lines, in order.
    new: Vec<Line>,
}

/// A line without its line feed, and whether it had one.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Line {
    text: String,
    newline: bool,
}

impl Line {
    fn new(text: &str, newline: bool) -> Self {
        Self {
            text: text.to_owned(),
            newline,
        }
    }
}

/// Applies `diff` to the tree at `root`.
pub fn apply(root: &Path, diff: &str) -> anyhow::Result<()> {
    let files = parse(diff)?;
    ensure!(!files.is_empty(), "the patch changes no file");
    for file in files {
        apply_file(root, &file)
            .with_context(|| format!("patching {}", file.change.target().display()))?;
    }
    Ok(())
}

fn apply_file(root: &Path, file: &FilePatch) -> anyhow::Result<()> {
    let mut lines = match &file.change {
        Change::Create(new) => {
            ensure!(!root.join(new).exists(), "created by the patch, but exists");
            Vec::new()
        }
        Change::Delete(old) | Change::Modify { old, .. } => {
            split(&std::fs::read_to_string(root.join(old))?)
        }
    };
    // Hunks are in order: later ones start after the lines earlier ones changed.
    let mut offset: isize = 0;
    let mut floor = 0;
    for (i, hunk) in file.hunks.iter().enumerate() {
        let expected = (hunk.old_start.saturating_sub(1) as isize + offset).max(0) as usize;
        let at = find(&lines, &hunk.old, expected, floor)
            .with_context(|| format!("hunk {} (line {}) does not apply", i + 1, hunk.old_start))?;
        lines.splice(at..at + hunk.old.len(), hunk.new.iter().cloned());
        offset += hunk.new.len() as isize - hunk.old.len() as isize;
        offset += at as isize - expected as isize;
        floor = at + hunk.new.len();
    }

    if let Change::Delete(old) = &file.change {
        ensure!(lines.is_empty(), "deleted by the patch, but lines remain");
        std::fs::remove_file(root.join(old))?;
        return Ok(());
    }
    let path = root.join(file.change.target());
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mode = (file.change.old())
        .and_then(|old| std::fs::metadata(root.join(old)).ok())
        .map(|m| m.permissions());
    std::fs::write(&path, join(&lines))?;
    if let Some(mode) = mode {
        std::fs::set_permissions(&path, mode)?;
    }
    if let Change::Modify { old, new } = &file.change
        && old != new
    {
        std::fs::remove_file(root.join(old))?;
    }
    Ok(())
}

/// Where `needle` occurs in `lines` at or after `floor`, nearest to `expected`.
fn find(lines: &[Line], needle: &[Line], expected: usize, floor: usize) -> Option<usize> {
    let last = lines.len().checked_sub(needle.len())?;
    let matches = |at: usize| at >= floor && at <= last && lines[at..at + needle.len()] == *needle;
    let expected = expected.min(last);
    (0..=lines.len()).find_map(|distance| {
        [
            expected.checked_add(distance),
            expected.checked_sub(distance),
        ]
        .into_iter()
        .flatten()
        .find(|&at| matches(at))
    })
}

fn split(text: &str) -> Vec<Line> {
    (text.split_inclusive('\n'))
        .map(|line| match line.strip_suffix('\n') {
            Some(text) => Line::new(text, true),
            None => Line::new(line, false),
        })
        .collect()
}

fn join(lines: &[Line]) -> String {
    let mut out = String::new();
    for line in lines {
        out.push_str(&line.text);
        if line.newline {
            out.push('\n');
        }
    }
    out
}

/// A `---`/`+++` path: `None` for `/dev/null`, else without its first component.
fn header_path(header: &str) -> anyhow::Result<Option<PathBuf>> {
    // `diff -u` appends a tab and a timestamp.
    let path = header.split('\t').next().unwrap_or(header).trim_end();
    if path == "/dev/null" {
        return Ok(None);
    }
    let stripped: PathBuf = Path::new(path).components().skip(1).collect();
    ensure!(
        !stripped.as_os_str().is_empty()
            && stripped
                .components()
                .all(|c| matches!(c, Component::Normal(_))),
        "unsafe or empty path {path:?}"
    );
    Ok(Some(stripped))
}

fn parse(diff: &str) -> anyhow::Result<Vec<FilePatch>> {
    let lines: Vec<&str> = diff.lines().collect();
    let mut files = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        let line = lines[i];
        if line.starts_with("GIT binary patch") || line.starts_with("rename from ") {
            bail!("unsupported patch line {line:?}");
        }
        let (Some(old), Some(new)) = (
            line.strip_prefix("--- "),
            lines.get(i + 1).and_then(|l| l.strip_prefix("+++ ")),
        ) else {
            // Mail headers, commit messages, `diff --git` and `index` lines.
            i += 1;
            continue;
        };
        let change = match (header_path(old)?, header_path(new)?) {
            (None, Some(new)) => Change::Create(new),
            (Some(old), None) => Change::Delete(old),
            (Some(old), Some(new)) => Change::Modify { old, new },
            (None, None) => bail!("a file from and to /dev/null"),
        };
        let mut file = FilePatch {
            change,
            hunks: Vec::new(),
        };
        i += 2;
        while let Some(header) = lines.get(i).and_then(|l| l.strip_prefix("@@ -")) {
            let (hunk, next) = parse_hunk(&lines, i, header)?;
            file.hunks.push(hunk);
            i = next;
        }
        ensure!(!file.hunks.is_empty(), "no hunk for {old}");
        files.push(file);
    }
    Ok(files)
}

/// Parses the hunk whose header (after `@@ -`) is at line `at`; returns it and the next line.
fn parse_hunk(lines: &[&str], at: usize, header: &str) -> anyhow::Result<(Hunk, usize)> {
    let ranges = header.split(" @@").next().unwrap_or_default();
    let (old, new) = ranges
        .split_once(" +")
        .with_context(|| format!("bad hunk header {header:?}"))?;
    let range = |range: &str| -> anyhow::Result<(usize, usize)> {
        let (start, len) = range.split_once(',').unwrap_or((range, "1"));
        Ok((start.parse()?, len.parse()?))
    };
    let (old_start, mut old_left) = range(old)?;
    let (_, mut new_left) = range(new)?;
    let mut hunk = Hunk {
        old_start,
        old: Vec::new(),
        new: Vec::new(),
    };
    // A line counted against what the header announced.
    let take = |left: &mut usize| -> anyhow::Result<()> {
        *left = left.checked_sub(1).context("hunk longer than its header")?;
        Ok(())
    };
    let mut i = at + 1;
    while old_left > 0 || new_left > 0 {
        let line = *lines.get(i).context("hunk ends early")?;
        // Some tools drop the space of empty context lines.
        let (kind, text) = match line.chars().next() {
            None => (' ', ""),
            Some(kind) => (kind, &line[1..]),
        };
        // `\ No newline at end of file` follows a line that has none.
        i += 1;
        let newline = !lines.get(i).is_some_and(|l| l.starts_with('\\'));
        if !newline {
            i += 1;
        }
        let line = Line::new(text, newline);
        match kind {
            ' ' => {
                take(&mut old_left)?;
                take(&mut new_left)?;
                hunk.old.push(line.clone());
                hunk.new.push(line);
            }
            '-' => {
                take(&mut old_left)?;
                hunk.old.push(line);
            }
            '+' => {
                take(&mut new_left)?;
                hunk.new.push(line);
            }
            _ => bail!("bad hunk line {line:?}"),
        }
    }
    Ok((hunk, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tree(files: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (path, contents) in files {
            let path = dir.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, contents).unwrap();
        }
        dir
    }

    #[test]
    fn applies_with_offset_and_creates_files() {
        let tree = tree(&[("src/a.c", "x\ny\none\ntwo\nthree\nfour\n")]);
        let dir = tree.path();
        let diff = "From abc Mon Sep 17 00:00:00 2001\nSubject: [PATCH] test\n\n---\n\
                    diff --git a/src/a.c b/src/a.c\n--- a/src/a.c\n+++ b/src/a.c\n\
                    @@ -1,3 +1,3 @@\n one\n-two\n+TWO\n three\n\
                    --- /dev/null\n+++ b/src/new.h\n@@ -0,0 +1,2 @@\n+/* new */\n+#define X 1\n";
        apply(dir, diff).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.join("src/a.c")).unwrap(),
            "x\ny\none\nTWO\nthree\nfour\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("src/new.h")).unwrap(),
            "/* new */\n#define X 1\n"
        );
    }

    #[test]
    fn rejects_mismatched_context() {
        let tree = tree(&[("a", "one\ntwo\n")]);
        let dir = tree.path();
        let diff = "--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n one\n-three\n+3\n";
        assert!(apply(dir, diff).is_err());
        assert_eq!(
            std::fs::read_to_string(dir.join("a")).unwrap(),
            "one\ntwo\n"
        );
    }

    #[test]
    fn handles_missing_final_newline() {
        let tree = tree(&[("a", "one\ntwo")]);
        let dir = tree.path();
        let diff =
            "--- a/a\n+++ b/a\n@@ -1,2 +1,2 @@\n one\n-two\n\\ No newline at end of file\n+2\n";
        apply(dir, diff).unwrap();
        assert_eq!(std::fs::read_to_string(dir.join("a")).unwrap(), "one\n2\n");
    }

    #[test]
    fn rejects_escaping_paths() {
        assert!(parse("--- a/../x\n+++ b/../x\n@@ -1 +1 @@\n-a\n+b\n").is_err());
    }
}

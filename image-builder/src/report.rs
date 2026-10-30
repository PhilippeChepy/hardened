//! The layout report printed at the end of a successful build: the partitions of the disk, the
//! files of the ESP and the root filesystem tree with the component owning each entry.
//!
//! Everything is read back from the finished artifacts (the GPT of the disk image, the FAT of the
//! ESP), not from what the build intended to write.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs::{self, File};
use std::path::Path;

use anyhow::Context;
use fatfs::{Dir, FileSystem, FsOptions};
use gpt::GptConfig;
use gpt::disk::LogicalBlockSize;
use uuid::Uuid;

use crate::image;
use crate::recipe::ComponentName;
use crate::rootfs::{Entry, Manifest};

const SECTOR: u64 = 512;

/// The partition types the image uses, by name.
const TYPES: &[(Uuid, &str)] = &[
    (image::ESP_TYPE, "EFI system"),
    (image::ROOT_X86_64_TYPE, "root (x86-64, erofs)"),
    (image::ROOT_X86_64_VERITY_TYPE, "root verity (x86-64)"),
    (image::VAR_TYPE, "var"),
];

/// The layout of disk image `disk`, its ESP image `esp`, and the root filesystem `manifest`
/// describes.
pub fn render(disk: &Path, esp: &Path, manifest: &Manifest) -> anyhow::Result<String> {
    let mut out = String::new();
    partitions(&mut out, disk)?;
    esp_tree(&mut out, esp)?;
    rootfs_tree(&mut out, manifest);
    Ok(out)
}

fn partitions(out: &mut String, disk: &Path) -> anyhow::Result<()> {
    let size = fs::metadata(disk)?.len();
    let table = GptConfig::new()
        .writable(false)
        .logical_block_size(LogicalBlockSize::Lb512)
        .open(disk)
        .with_context(|| format!("reading the GPT of {}", disk.display()))?;
    let _ = writeln!(out, "Disk ({}, GPT {})", human(size), table.guid());
    let _ = writeln!(
        out,
        "  #  {:<20} {:<22} {:>10} {:>10}  UUID",
        "name", "type", "offset", "size"
    );
    for (number, partition) in table.partitions() {
        let kind = TYPES
            .iter()
            .find(|(guid, _)| *guid == partition.part_type_guid.guid)
            .map_or("unknown", |(_, name)| name);
        let start = partition.first_lba * SECTOR;
        let length = (partition.last_lba + 1 - partition.first_lba) * SECTOR;
        let _ = writeln!(
            out,
            "  {number}  {:<20} {kind:<22} {:>10} {:>10}  {}",
            partition.name,
            human(start),
            human(length),
            partition.part_guid
        );
    }
    let _ = writeln!(
        out,
        "  (storage-controller extends the last partition, var, to the end of the disk at boot)"
    );
    Ok(())
}

fn esp_tree(out: &mut String, esp: &Path) -> anyhow::Result<()> {
    fn walk(dir: &Dir<'_, File>, tree: &mut Tree, prefix: &str) -> anyhow::Result<()> {
        for entry in dir.iter() {
            let entry = entry?;
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let path = format!("{prefix}{name}");
            if entry.is_dir() {
                tree.insert(&path, Node::dir(None));
                walk(&entry.to_dir(), tree, &format!("{path}/"))?;
            } else {
                tree.insert(&path, Node::file(entry.len(), None, None));
            }
        }
        Ok(())
    }

    let file = File::open(esp).with_context(|| esp.display().to_string())?;
    let esp = FileSystem::new(file, FsOptions::new())?;
    let mut tree = Tree::default();
    walk(&esp.root_dir(), &mut tree, "")?;
    let _ = writeln!(out, "\nESP (partition 1)");
    tree.render(out, "  ");
    Ok(())
}

fn rootfs_tree(out: &mut String, manifest: &Manifest) {
    let mut tree = Tree::default();
    let mut totals: BTreeMap<&ComponentName, Total> = BTreeMap::new();
    for (path, entry) in &manifest.entries {
        let total = totals.entry(entry.component()).or_default();
        total.entries += 1;
        let node = match entry {
            Entry::Dir { component, .. } => Node::dir(Some(component)),
            Entry::File {
                component,
                mode,
                size,
                ..
            } => {
                total.bytes += size;
                Node::file(*size, Some(format!("{mode:04o}")), Some(component))
            }
            Entry::Symlink { component, target } => Node::symlink(target, component),
        };
        tree.insert(path, node);
    }
    let _ = writeln!(
        out,
        "\nRoot filesystem (partitions 2 + 3, read-only, dm-verity)"
    );
    tree.render(out, "  ");
    let _ = writeln!(out, "\nBy component");
    for (component, total) in totals {
        let _ = writeln!(
            out,
            "  {:<16} {:>5} entries  {:>10}",
            component.to_string(),
            total.entries,
            human(total.bytes)
        );
    }
}

/// What a component ships in the root filesystem.
#[derive(Debug, Default)]
struct Total {
    entries: usize,
    /// The size of its files.
    bytes: u64,
}

/// What a tree line describes.
#[derive(Debug, Default)]
struct Node {
    dir: bool,
    label: String,
    children: Tree,
}

impl Node {
    fn dir(component: Option<&ComponentName>) -> Self {
        Self {
            dir: true,
            label: component.map(|c| format!("  [{c}]")).unwrap_or_default(),
            ..Self::default()
        }
    }

    fn file(size: u64, mode: Option<String>, component: Option<&ComponentName>) -> Self {
        let mut label = format!("  {}", human(size));
        if let Some(mode) = mode {
            let _ = write!(label, "  {mode}");
        }
        if let Some(component) = component {
            let _ = write!(label, "  [{component}]");
        }
        Self {
            label,
            ..Self::default()
        }
    }

    fn symlink(target: &str, component: &ComponentName) -> Self {
        Self {
            label: format!(" -> {target}  [{component}]"),
            ..Self::default()
        }
    }
}

/// Entries by path component, so children sort under their parent.
#[derive(Debug, Default)]
struct Tree(BTreeMap<String, Node>);

impl Tree {
    /// Inserts `node` at `path`, keeping the children a directory may already have.
    fn insert(&mut self, path: &str, node: Node) {
        let (parents, name) = path.rsplit_once('/').unwrap_or(("", path));
        let mut tree = self;
        for parent in parents.split('/').filter(|p| !p.is_empty()) {
            tree = &mut tree.0.entry(parent.to_owned()).or_default().children;
        }
        let slot = tree.0.entry(name.to_owned()).or_default();
        slot.dir = node.dir;
        slot.label = node.label;
    }

    fn render(&self, out: &mut String, indent: &str) {
        let count = self.0.len();
        for (i, (name, node)) in self.0.iter().enumerate() {
            let last = i + 1 == count;
            let branch = if last { "└── " } else { "├── " };
            let slash = if node.dir { "/" } else { "" };
            let _ = writeln!(out, "{indent}{branch}{name}{slash}{}", node.label);
            let deeper = format!("{indent}{}", if last { "    " } else { "│   " });
            node.children.render(out, &deeper);
        }
    }
}

/// Size in bytes, KiB, MiB or GiB.
#[must_use]
fn human(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

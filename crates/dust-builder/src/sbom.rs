//! CycloneDX 1.6 SBOM of the image.
//!
//! One component per recipe (with its source archives, checksums and license), nesting the Go
//! modules and Rust crates compiled into its binaries, plus the toolchain standard libraries that
//! end up linked in. The metadata records the image checksum, the dm-verity root hash, the kernel
//! command line and the pinned images the build bootstraps from, so the SBOM is tied to exactly
//! one image.

use std::collections::BTreeMap;

use anyhow::Context;
use serde_json::{Value, json};

use crate::build::Built;
use crate::recipe::ComponentName;
use crate::rootfs::Manifest;
use crate::sha256::Sha256;

pub struct Sbom<'a> {
    pub version: &'a str,
    pub components: &'a [&'a Built],
    /// The pinned images of the seeds.
    pub bootstrap: &'a [String],
    pub manifest: &'a Manifest,
    pub image_sha256: Sha256,
    pub roothash: Sha256,
    pub cmdline: &'a str,
}

impl Sbom<'_> {
    pub fn render(&self) -> anyhow::Result<Value> {
        let mut files_per_component: BTreeMap<&ComponentName, usize> = BTreeMap::new();
        for entry in self.manifest.entries.values() {
            *files_per_component.entry(entry.component()).or_default() += 1;
        }

        let mut components = Vec::new();
        for built in self.components {
            let meta = &built.recipe.meta;
            let mut component = json!({
                "type": meta.kind,
                "bom-ref": built.unit.to_string(),
                "name": meta.name,
                "version": meta.version,
                "description": meta.summary,
                "licenses": [{ "expression": meta.license }],
                "purl": meta.purl,
                "externalReferences": external_references(built),
                "properties": [
                    { "name": "hardened:build-key", "value": built.key },
                    { "name": "hardened:target", "value": built.unit.target },
                    { "name": "hardened:rootfs-entries",
                      "value": files_per_component.get(&meta.name).copied().unwrap_or(0).to_string() },
                ],
            });
            if let Some(cpe) = &meta.cpe {
                component["cpe"] = json!(cpe);
            }
            let nested = nested_components(built)?;
            if !nested.is_empty() {
                component["components"] = Value::Array(nested);
            }
            components.push(component);
        }

        let refs: Vec<String> = self.components.iter().map(|b| b.unit.to_string()).collect();
        let mut dependencies = vec![json!({ "ref": "hardened", "dependsOn": refs })];
        for built in self.components {
            let depends: Vec<String> = built.recipe.depends().into_iter().map(ToString::to_string).collect();
            dependencies.push(json!({
                "ref": built.unit.to_string(),
                "dependsOn": depends,
            }));
        }

        let serial = uuid::Builder::from_random_bytes(self.image_sha256.prefix()).into_uuid();

        Ok(json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "serialNumber": format!("urn:uuid:{serial}"),
            "version": 1,
            "metadata": {
                "timestamp": rfc3339(crate::SOURCE_DATE_EPOCH),
                "tools": { "components": [{
                    "type": "application",
                    "name": "dust-builder",
                    "version": self.version,
                }]},
                "component": {
                    "type": "operating-system",
                    "bom-ref": "hardened",
                    "name": "hardened",
                    "version": self.version,
                    "hashes": [{ "alg": "SHA-256", "content": self.image_sha256 }],
                    "properties": [
                        { "name": "hardened:image-format", "value": "qcow2" },
                        { "name": "hardened:architecture", "value": "x86_64" },
                        { "name": "hardened:verity-roothash", "value": self.roothash },
                        { "name": "hardened:kernel-cmdline", "value": self.cmdline },
                        { "name": "hardened:bootstrap-images", "value": self.bootstrap.join(" ") },
                    ],
                },
            },
            "components": components,
            "dependencies": dependencies,
        }))
    }
}

fn external_references(built: &Built) -> Vec<Value> {
    let mut refs = vec![json!({ "type": "website", "url": built.recipe.meta.homepage })];
    for source in &built.recipe.plan.sources {
        refs.push(json!({
            "type": "source-distribution",
            "url": source.url,
            "hashes": [{ "alg": "SHA-256", "content": source.sha256 }],
        }));
    }
    refs
}

/// The inventories a build records for the SBOM, in `sbom/<name>.<extension>`: the libraries
/// linked into the component's binaries that its own metadata does not describe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inventory {
    /// `go version -m` output: the Go modules and standard library of a binary.
    GoBuildInfo,
    /// `cargo tree --format '{p}|{l}'` output: the crates of Rust binaries.
    CargoTree,
    /// `rustc --version`: the Rust standard library linked in.
    RustToolchain,
}

/// A library listed by an inventory.
struct Library {
    name: String,
    version: String,
    purl: String,
    license: Option<String>,
}

impl Inventory {
    const ALL: [Self; 3] = [Self::GoBuildInfo, Self::CargoTree, Self::RustToolchain];

    pub fn extension(self) -> &'static str {
        match self {
            Self::GoBuildInfo => "gomod",
            Self::CargoTree => "crates",
            Self::RustToolchain => "toolchain",
        }
    }

    fn libraries(self, text: &str) -> Vec<Library> {
        match self {
            Self::GoBuildInfo => (parse_go_version_m(text).into_iter())
                .map(|(name, version)| Library {
                    purl: format!("pkg:golang/{name}@{version}"),
                    name,
                    version,
                    license: None,
                })
                .collect(),
            Self::CargoTree => (parse_cargo_tree(text).into_iter())
                .map(|(name, version, license)| Library {
                    purl: format!("pkg:cargo/{name}@{version}"),
                    name,
                    version,
                    license,
                })
                .collect(),
            // `rustc 1.99.1 (58cf8f9c3 2026-10-13)`
            Self::RustToolchain => (text.split_whitespace().nth(1))
                .map(|version| Library {
                    name: "rust-std".to_owned(),
                    version: version.to_owned(),
                    purl: format!("pkg:generic/rust-std@{version}"),
                    license: Some("MIT OR Apache-2.0".to_owned()),
                })
                .into_iter()
                .collect(),
        }
    }
}

/// The libraries the build's inventories list, as CycloneDX components.
fn nested_components(built: &Built) -> anyhow::Result<Vec<Value>> {
    let mut nested: BTreeMap<String, Value> = BTreeMap::new();
    let dir = built.sbom();
    if !dir.exists() {
        return Ok(Vec::new());
    }
    for entry in std::fs::read_dir(&dir)? {
        let path = entry?.path();
        let extension = path.extension().and_then(|e| e.to_str());
        let kind = Inventory::ALL
            .into_iter()
            .find(|kind| Some(kind.extension()) == extension)
            .with_context(|| format!("unknown SBOM inventory {}", path.display()))?;
        for library in kind.libraries(&std::fs::read_to_string(&path)?) {
            let mut component = json!({
                "type": "library",
                "bom-ref": library.purl,
                "name": library.name,
                "version": library.version,
                "purl": library.purl,
            });
            if let Some(license) = library.license {
                component["licenses"] = json!([{ "expression": license }]);
            }
            nested.insert(library.purl, component);
        }
    }
    Ok(nested.into_values().collect())
}

/// Parses `go version -m` output into (module, version) pairs, including the Go standard library.
fn parse_go_version_m(text: &str) -> Vec<(String, String)> {
    let mut modules = Vec::new();
    let mut lines = text.lines();
    if let Some(first) = lines.next()
        && let Some(go) = first.rsplit(' ').next().and_then(|v| v.strip_prefix("go"))
    {
        modules.push(("stdlib".to_owned(), go.to_owned()));
    }
    for line in lines {
        let fields: Vec<&str> = line.split('\t').filter(|f| !f.is_empty()).collect();
        match fields.as_slice() {
            // A replaced module: the replacement is what was compiled.
            ["=>", path, version, ..] => {
                modules.pop();
                modules.push(((*path).to_owned(), (*version).to_owned()));
            }
            ["dep", path, version, ..] => modules.push(((*path).to_owned(), (*version).to_owned())),
            _ => {}
        }
    }
    modules
}

/// Parses `cargo tree --format '{p}|{l}'` lines, skipping in-tree (path) crates.
fn parse_cargo_tree(text: &str) -> Vec<(String, String, Option<String>)> {
    text.lines()
        .filter(|line| !line.contains("(/"))
        .filter_map(|line| {
            let (package, license) = line.split_once('|')?;
            let mut words = package.split_whitespace();
            let name = words.next()?.to_owned();
            let version = words.next()?.strip_prefix('v')?.to_owned();
            let license = Some(license.trim().to_owned()).filter(|l| !l.is_empty());
            Some((name, version, license))
        })
        .collect()
}

/// Formats a Unix timestamp as RFC 3339 UTC (civil-from-days, Howard Hinnant's algorithm).
fn rfc3339(epoch: u64) -> String {
    let days = (epoch / 86_400) as i64;
    let secs = epoch % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        secs / 3600,
        secs / 60 % 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_build_info() {
        let text = "/out/root/usr/bin/runc: go1.27.3\n\
                    \tpath\tgithub.com/opencontainers/runc\n\
                    \tmod\tgithub.com/opencontainers/runc\t(devel)\t\n\
                    \tdep\tgithub.com/cilium/ebpf\tv0.17.3\th1:abc=\n\
                    \tdep\tgolang.org/x/sys\tv0.30.0\n\
                    \t=>\tgolang.org/x/sys\tv0.31.0\th1:def=\n\
                    \tbuild\tCGO_ENABLED=1\n";
        assert_eq!(
            parse_go_version_m(text),
            vec![
                ("stdlib".into(), "1.27.3".into()),
                ("github.com/cilium/ebpf".into(), "v0.17.3".into()),
                ("golang.org/x/sys".into(), "v0.31.0".into()),
            ]
        );
    }

    #[test]
    fn parses_cargo_tree() {
        let text = "dust-init v0.1.0 (/src/crates/dust)|Apache-2.0\n\
                    tokio v1.54.1|MIT\n\
                    ring v0.17.14|Apache-2.0 AND ISC\n";
        assert_eq!(
            parse_cargo_tree(text),
            vec![
                ("tokio".into(), "1.54.1".into(), Some("MIT".into())),
                ("ring".into(), "0.17.14".into(), Some("Apache-2.0 AND ISC".into())),
            ]
        );
    }

    #[test]
    fn formats_timestamps() {
        assert_eq!(rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339(crate::SOURCE_DATE_EPOCH), "2026-01-01T00:00:00Z");
        assert_eq!(rfc3339(951_782_400), "2000-02-29T00:00:00Z");
    }
}

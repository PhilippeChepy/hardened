//! Where a recipe's releases are listed, inferred from its source's URL (or its `[update]`
//! table), and the versions found there.

use std::collections::BTreeMap;

use anyhow::{Context, bail};
use serde::Deserialize;

use crate::sha256::Sha256;
use crate::update::http;
use crate::update::policy::Policy;
use crate::update::template;
use crate::update::version::Version;

/// Where releases are listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// The tags of a git repository (over git's smart HTTP: any host, no API), `tag` naming
    /// them.
    GitTags { repository: String, tag: String },
    /// A page naming the files (a directory listing), `file` matching their names.
    Listing { page: String, file: String },
    /// PyPI's metadata of a project, with its files' checksums.
    PyPi { project: String },
    /// go.dev's list of Go releases, with their files' checksums.
    Go,
    /// Rust's current stable release.
    Rust,
}

/// What a probe found: the releases, and the checksums the index publishes, by version and
/// file name.
#[derive(Debug, Default)]
pub struct Found {
    pub versions: Vec<Version>,
    pub checksums: BTreeMap<(String, String), Sha256>,
}

impl Probe {
    /// The probe of a source downloaded from `url` (`{version}` in it), as `policy` adjusts it;
    /// none when nothing names its releases.
    #[must_use]
    pub fn infer(url: &str, policy: &Policy) -> Option<Self> {
        let tag = || (policy.tag.clone()).unwrap_or_else(|| "v{version}".to_owned());
        if let Some(repository) = &policy.repository {
            return Some(Self::GitTags {
                repository: repository.clone(),
                tag: tag(),
            });
        }
        let file = url.rsplit('/').next().unwrap_or_default();
        if let Some(page) = &policy.listing {
            return Some(Self::Listing {
                page: page.clone(),
                file: file.to_owned(),
            });
        }
        if let Some(path) = url.strip_prefix("https://github.com/") {
            let mut parts = path.splitn(4, '/');
            let (owner, repo, kind, rest) =
                (parts.next()?, parts.next()?, parts.next()?, parts.next()?);
            let tag = match kind {
                "archive" => {
                    let tag = rest.strip_prefix("refs/tags/").unwrap_or(rest);
                    tag.strip_suffix(".tar.gz")
                        .or_else(|| tag.strip_suffix(".zip"))?
                        .to_owned()
                }
                "releases" => rest
                    .strip_prefix("download/")?
                    .split('/')
                    .next()?
                    .to_owned(),
                _ => return None,
            };
            if !tag.contains(template::VERSION) {
                return None;
            }
            return Some(Self::GitTags {
                repository: format!("https://github.com/{owner}/{repo}"),
                tag: policy.tag.clone().unwrap_or(tag),
            });
        }
        if let Some((repository, _)) = url.split_once("/-/archive/") {
            // GitLab: `<repository>/-/archive/<tag>/<file>`.
            let tag = url
                .split("/-/archive/")
                .nth(1)?
                .split('/')
                .next()?
                .to_owned();
            return Some(Self::GitTags {
                repository: repository.to_owned(),
                tag: policy.tag.clone().unwrap_or(tag),
            });
        }
        if let Some((repository, _)) = url.split_once("/snapshot/") {
            // cgit (git.kernel.org): `<repository>/snapshot/<name>-<version>.tar.gz`.
            return Some(Self::GitTags {
                repository: repository.to_owned(),
                tag: tag(),
            });
        }
        if let Some(path) = url.strip_prefix("https://files.pythonhosted.org/packages/") {
            // `packages/<py3|source>/<initial>/<project>/<file>`.
            let project = path.split('/').nth(2)?;
            return Some(Self::PyPi {
                project: project.to_owned(),
            });
        }
        if url.starts_with("https://go.dev/dl/") {
            return Some(Self::Go);
        }
        if url.starts_with("https://static.rust-lang.org/dist/") {
            return Some(Self::Rust);
        }
        if url.contains("raw.githubusercontent.com") {
            return None;
        }
        // A directory listing: the directory above the first part naming the version (a
        // subdirectory's name with its `/`, as listings write it).
        let at = url.find(template::VERSION)?;
        let start = url[..at].rfind('/')? + 1;
        let end = url[at..].find('/').map_or(url.len(), |end| at + end + 1);
        Some(Self::Listing {
            page: url[..start].to_owned(),
            file: url[start..end].to_owned(),
        })
    }

    /// The releases it lists.
    ///
    /// # Errors
    ///
    /// When the listing cannot be read or understood.
    pub fn probe(&self) -> anyhow::Result<Found> {
        let mut found = Found::default();
        let versions: Vec<String> = match self {
            Self::GitTags { repository, tag } => {
                let tags = git_tags(repository)?;
                let names = format!("\n{}\n", tags.join("\n"));
                template::versions_in(&format!("\n{tag}\n"), &names)
                    .into_iter()
                    .collect()
            }
            Self::Listing { page, file } => {
                let text = http::text(page)?;
                template::versions_in(file, &text).into_iter().collect()
            }
            Self::PyPi { project } => {
                let url = format!("https://pypi.org/pypi/{project}/json");
                let index: PyPiIndex = serde_json::from_str(&http::text(&url)?)
                    .with_context(|| format!("{url}: unexpected document"))?;
                let mut versions = Vec::new();
                for (version, files) in index.releases {
                    let files: Vec<PyPiFile> =
                        files.into_iter().filter(|file| !file.yanked).collect();
                    if files.is_empty() {
                        continue;
                    }
                    for file in files {
                        if let Ok(sha256) = file.digests.sha256.parse() {
                            found
                                .checksums
                                .insert((version.clone(), file.filename), sha256);
                        }
                    }
                    versions.push(version);
                }
                versions
            }
            Self::Go => {
                let url = "https://go.dev/dl/?mode=json&include=all";
                let releases: Vec<GoRelease> = serde_json::from_str(&http::text(url)?)
                    .with_context(|| format!("{url}: unexpected document"))?;
                let mut versions = Vec::new();
                for release in releases.into_iter().filter(|release| release.stable) {
                    let Some(version) = release.version.strip_prefix("go") else {
                        continue;
                    };
                    for file in release.files {
                        if let Ok(sha256) = file.sha256.parse() {
                            found
                                .checksums
                                .insert((version.to_owned(), file.filename), sha256);
                        }
                    }
                    versions.push(version.to_owned());
                }
                versions
            }
            Self::Rust => {
                let url = "https://static.rust-lang.org/dist/channel-rust-stable.toml";
                let channel: RustChannel = toml::from_str(&http::text(url)?)
                    .with_context(|| format!("{url}: unexpected document"))?;
                // `1.91.0 (f8297e351 2025-10-28)`.
                let version = channel.pkg.rustc.version.split(' ').next();
                version.map(str::to_owned).into_iter().collect()
            }
        };
        found.versions = versions.iter().filter_map(|v| Version::parse(v)).collect();
        Ok(found)
    }
}

impl std::fmt::Display for Probe {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GitTags { repository, tag } => write!(f, "tags {tag} of {repository}"),
            Self::Listing { page, file } => write!(f, "{file} in {page}"),
            Self::PyPi { project } => write!(f, "PyPI's {project}"),
            Self::Go => f.write_str("go.dev's releases"),
            Self::Rust => f.write_str("Rust's stable channel"),
        }
    }
}

/// The tags of the git repository at `repository` (an HTTPS URL), from the refs its smart HTTP
/// service advertises; peeled tags (`^{}`) once.
fn git_tags(repository: &str) -> anyhow::Result<Vec<String>> {
    let base = repository.trim_end_matches('/');
    let base = if base.ends_with(".git") {
        base.to_owned()
    } else {
        format!("{base}.git")
    };
    let url = format!("{base}/info/refs?service=git-upload-pack");
    let advertisement = http::bytes(&url)?;
    let mut tags = parse_refs(&advertisement).with_context(|| format!("{url}: unexpected refs"))?;
    tags.sort();
    tags.dedup();
    Ok(tags)
}

/// The tag names of a git ref advertisement (protocol v0, pkt-lines).
fn parse_refs(mut data: &[u8]) -> anyhow::Result<Vec<String>> {
    let mut tags = Vec::new();
    while data.len() >= 4 {
        let length = std::str::from_utf8(&data[..4])
            .ok()
            .and_then(|hex| usize::from_str_radix(hex, 16).ok())
            .context("invalid pkt-line length")?;
        if length == 0 {
            // A flush packet.
            data = &data[4..];
            continue;
        }
        if length < 4 || length > data.len() {
            bail!("truncated pkt-line");
        }
        let line = &data[4..length];
        data = &data[length..];
        let line = String::from_utf8_lossy(line);
        let line = line.split('\0').next().unwrap_or_default().trim_end();
        if let Some((_, name)) = line.split_once(' ')
            && let Some(tag) = name.strip_prefix("refs/tags/")
        {
            tags.push(tag.trim_end_matches("^{}").to_owned());
        }
    }
    Ok(tags)
}

#[derive(Deserialize)]
struct PyPiIndex {
    releases: BTreeMap<String, Vec<PyPiFile>>,
}

#[derive(Deserialize)]
struct PyPiFile {
    filename: String,
    digests: PyPiDigests,
    #[serde(default)]
    yanked: bool,
}

#[derive(Deserialize)]
struct PyPiDigests {
    sha256: String,
}

#[derive(Deserialize)]
struct GoRelease {
    version: String,
    stable: bool,
    files: Vec<GoFile>,
}

#[derive(Deserialize)]
struct GoFile {
    filename: String,
    sha256: String,
}

#[derive(Deserialize)]
struct RustChannel {
    pkg: RustPackages,
}

#[derive(Deserialize)]
struct RustPackages {
    rustc: RustPackage,
}

#[derive(Deserialize)]
struct RustPackage {
    version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn infer(url: &str) -> Option<Probe> {
        Probe::infer(url, &Policy::default())
    }

    fn tags(repository: &str, tag: &str) -> Option<Probe> {
        Some(Probe::GitTags {
            repository: repository.to_owned(),
            tag: tag.to_owned(),
        })
    }

    fn listing(page: &str, file: &str) -> Option<Probe> {
        Some(Probe::Listing {
            page: page.to_owned(),
            file: file.to_owned(),
        })
    }

    #[test]
    fn inferred_from_the_url() {
        assert_eq!(
            infer(
                "https://github.com/NVIDIA/k8s-device-plugin/archive/refs/tags/v{version}.tar.gz"
            ),
            tags("https://github.com/NVIDIA/k8s-device-plugin", "v{version}")
        );
        assert_eq!(
            infer("https://github.com/x/y/releases/download/y-{version}/y-{version}.tar.xz"),
            tags("https://github.com/x/y", "y-{version}")
        );
        assert_eq!(
            infer(
                "https://gitlab.freedesktop.org/slirp/libslirp/-/archive/v{version}/libslirp-v{version}.tar.gz"
            ),
            tags(
                "https://gitlab.freedesktop.org/slirp/libslirp",
                "v{version}"
            )
        );
        assert_eq!(
            infer("https://ftp.gnu.org/gnu/glibc/glibc-{version}.tar.xz"),
            listing("https://ftp.gnu.org/gnu/glibc/", "glibc-{version}.tar.xz")
        );
        assert_eq!(
            infer("https://www.python.org/ftp/python/{version}/Python-{version}.tar.xz"),
            listing("https://www.python.org/ftp/python/", "{version}/")
        );
        assert_eq!(
            infer(
                "https://files.pythonhosted.org/packages/py3/w/wheel/wheel-{version}-py3-none-any.whl"
            ),
            Some(Probe::PyPi {
                project: "wheel".to_owned()
            })
        );
        assert_eq!(
            infer("https://go.dev/dl/go{version}.src.tar.gz"),
            Some(Probe::Go)
        );
        // A commit, not a release.
        assert_eq!(
            infer("https://github.com/x/y/archive/0123abcd.tar.gz"),
            None
        );
    }

    #[test]
    fn the_policy_names_the_repository_and_tags() {
        let policy = Policy {
            repository: Some("https://github.com/tianocore/edk2".to_owned()),
            tag: Some("edk2-{version}".to_owned()),
            ..Policy::default()
        };
        assert_eq!(
            Probe::infer("https://example.org/x-{version}.tar.gz", &policy),
            tags("https://github.com/tianocore/edk2", "edk2-{version}")
        );
    }

    #[test]
    fn refs_of_an_advertisement() {
        let mut data = Vec::new();
        for line in [
            "# service=git-upload-pack\n",
            "",
            "1111111111111111111111111111111111111111 HEAD\0multi_ack\n",
            "2222222222222222222222222222222222222222 refs/heads/main\n",
            "3333333333333333333333333333333333333333 refs/tags/v1.0\n",
            "4444444444444444444444444444444444444444 refs/tags/v1.0^{}\n",
        ] {
            if line.is_empty() {
                data.extend(b"0000");
            } else {
                data.extend(format!("{:04x}{line}", line.len() + 4).as_bytes());
            }
        }
        data.extend(b"0000");
        assert_eq!(parse_refs(&data).unwrap(), ["v1.0", "v1.0"]);
    }
}

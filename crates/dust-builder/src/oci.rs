//! Container images produced by components, shipped in the root filesystem.
//!
//! CRI only runs images, so the containers of the OS itself (the pod sandbox's pause process)
//! are "from scratch" images: a component declares one
//! ([`crate::recipe::ContainerImage`], with [`crate::recipe::Build::container_image`]) and
//! installs its files into it. After the component builds, dust-builder archives that tree as a
//! single-layer OCI image layout. Image assembly then copies every
//! archive to `/usr/share/hardened/images/`, where dust-init imports them into containerd at boot.
//! Being part of the dm-verity protected root, they need no registry, network or signature.
//!
//! Archives are reproducible: entries are sorted, owned by root, stamped with
//! `SOURCE_DATE_EPOCH`, and the JSON documents carry no timestamps.

use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, bail, ensure};
use serde_json::{Value, json};
use walkdir::WalkDir;

use crate::recipe::ContainerImage;
use crate::sha256::Sha256;

/// Directory of the image archives in the root filesystem (no leading slash).
pub const IMAGES_DIR: &str = "usr/share/hardened/images";

const LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";

/// The reference of an image produced by a component.
pub fn reference(name: &str, version: &str) -> String {
    format!("localhost/hardened/{name}:{version}")
}

/// Archives the image tree `tree` (the files a build placed) as an OCI image layout.
pub fn archive(tree: &Path, spec: &ContainerImage, version: &str, epoch: u64) -> anyhow::Result<Vec<u8>> {
    let entrypoint = spec.entrypoint;
    ensure!(
        tree.join(entrypoint.trim_start_matches('/')).is_file(),
        "the entrypoint {entrypoint} of image {} was not placed by the build",
        spec.name
    );
    let reference = spec.reference(version);
    let layer = layer(tree, epoch)?;
    let layer_digest = Sha256::digest(&layer);
    let config = to_json(&json!({
        "architecture": "amd64",
        "os": "linux",
        "config": {
            "Entrypoint": [entrypoint],
            "User": format!("{}:{}", spec.user.0, spec.user.1),
            "WorkingDir": "/",
        },
        "rootfs": { "type": "layers", "diff_ids": [format!("sha256:{layer_digest}")] },
    }))?;
    let manifest = to_json(&json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "config": descriptor(CONFIG_MEDIA_TYPE, &config),
        "layers": [descriptor(LAYER_MEDIA_TYPE, &layer)],
    }))?;
    let mut manifest_descriptor = descriptor(MANIFEST_MEDIA_TYPE, &manifest);
    manifest_descriptor["annotations"] = json!({
        "io.containerd.image.name": reference,
        "org.opencontainers.image.ref.name": version,
    });
    let index = to_json(&json!({
        "schemaVersion": 2,
        "mediaType": INDEX_MEDIA_TYPE,
        "manifests": [manifest_descriptor],
    }))?;

    let mut blobs: BTreeMap<String, &[u8]> = BTreeMap::new();
    for blob in [&config, &manifest, &layer] {
        blobs.insert(Sha256::digest(blob).to_string(), blob);
    }
    let mut archive = Tar::new(epoch);
    archive.file("oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#, 0o644)?;
    archive.file("index.json", &index, 0o644)?;
    archive.dir("blobs", 0o755)?;
    archive.dir("blobs/sha256", 0o755)?;
    for (digest, blob) in blobs {
        archive.file(&format!("blobs/sha256/{digest}"), blob, 0o644)?;
    }
    archive.finish()
}

/// The image's single layer: every entry below `tree`, sorted, with its permission bits.
fn layer(tree: &Path, epoch: u64) -> anyhow::Result<Vec<u8>> {
    let mut layer = Tar::new(epoch);
    for entry in WalkDir::new(tree).sort_by_file_name().min_depth(1) {
        let entry = entry?;
        let path = entry.path().strip_prefix(tree)?.to_string_lossy().into_owned();
        let mode = entry.metadata()?.mode() & 0o7777;
        ensure!(
            mode & 0o7000 == 0,
            "/{path}: no setuid, setgid or sticky bits in images"
        );
        let kind = entry.file_type();
        if kind.is_dir() {
            layer.dir(&path, mode)?;
        } else if kind.is_file() {
            layer.file(&path, &std::fs::read(entry.path())?, mode)?;
        } else if kind.is_symlink() {
            let target = std::fs::read_link(entry.path())?;
            layer.symlink(&path, &target.to_string_lossy())?;
        } else {
            bail!("/{path}: unsupported file type");
        }
    }
    layer.finish().context("archiving the image layer")
}

fn descriptor(media_type: &str, blob: &[u8]) -> Value {
    json!({
        "mediaType": media_type,
        "digest": format!("sha256:{}", Sha256::digest(blob)),
        "size": blob.len(),
    })
}

fn to_json(value: &Value) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(value)?)
}

/// A reproducible tar archive: every entry owned by root and stamped with the same time.
struct Tar {
    builder: tar::Builder<Vec<u8>>,
    epoch: u64,
}

impl Tar {
    fn new(epoch: u64) -> Self {
        Self {
            builder: tar::Builder::new(Vec::new()),
            epoch,
        }
    }

    fn header(&self, kind: tar::EntryType, mode: u32, size: u64) -> tar::Header {
        let mut header = tar::Header::new_ustar();
        header.set_entry_type(kind);
        header.set_mode(mode);
        header.set_size(size);
        header.set_mtime(self.epoch);
        header.set_uid(0);
        header.set_gid(0);
        header
    }

    fn dir(&mut self, path: &str, mode: u32) -> anyhow::Result<()> {
        let mut header = self.header(tar::EntryType::Directory, mode, 0);
        self.builder
            .append_data(&mut header, format!("{path}/"), std::io::empty())?;
        Ok(())
    }

    fn file(&mut self, path: &str, contents: &[u8], mode: u32) -> anyhow::Result<()> {
        let mut header = self.header(tar::EntryType::Regular, mode, contents.len() as u64);
        self.builder.append_data(&mut header, path, contents)?;
        Ok(())
    }

    fn symlink(&mut self, path: &str, target: &str) -> anyhow::Result<()> {
        let mut header = self.header(tar::EntryType::Symlink, 0o777, 0);
        self.builder.append_link(&mut header, path, target)?;
        Ok(())
    }

    fn finish(self) -> anyhow::Result<Vec<u8>> {
        Ok(self.builder.into_inner()?)
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn spec() -> ContainerImage {
        ContainerImage {
            name: crate::name!("pause"),
            entrypoint: "/pause",
            user: (65535, 65535),
        }
    }

    fn tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let binary = dir.path().join("pause");
        std::fs::write(&binary, b"\x7fELF fake").unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::create_dir(dir.path().join("etc")).unwrap();
        dir
    }

    fn entries(archive: &[u8]) -> BTreeMap<String, (tar::Header, Vec<u8>)> {
        let mut tar = tar::Archive::new(archive);
        tar.entries()
            .unwrap()
            .map(|entry| {
                let mut entry = entry.unwrap();
                let path = entry.path().unwrap().to_string_lossy().into_owned();
                let header = entry.header().clone();
                let mut data = Vec::new();
                std::io::Read::read_to_end(&mut entry, &mut data).unwrap();
                (path, (header, data))
            })
            .collect()
    }

    #[test]
    fn archives_are_reproducible_oci_layouts() {
        let tree = tree();
        let first = archive(tree.path(), &spec(), "3.10.2", 42).unwrap();
        assert_eq!(first, archive(tree.path(), &spec(), "3.10.2", 42).unwrap());

        let files = entries(&first);
        let index: Value = serde_json::from_slice(&files["index.json"].1).unwrap();
        let descriptor = &index["manifests"][0];
        assert_eq!(
            descriptor["annotations"]["io.containerd.image.name"],
            "localhost/hardened/pause:3.10.2"
        );
        for (path, (_, data)) in &files {
            if let Some(digest) = path.strip_prefix("blobs/sha256/").filter(|d| !d.is_empty()) {
                assert_eq!(digest, Sha256::digest(data).to_string());
            }
        }
        let blob = |digest: &str| &files[&format!("blobs/sha256/{}", digest.trim_start_matches("sha256:"))].1;
        let manifest: Value = serde_json::from_slice(blob(descriptor["digest"].as_str().unwrap())).unwrap();
        let config: Value = serde_json::from_slice(blob(manifest["config"]["digest"].as_str().unwrap())).unwrap();
        assert_eq!(config["config"]["User"], "65535:65535");
        let layer = entries(blob(manifest["layers"][0]["digest"].as_str().unwrap()));
        assert_eq!(
            layer.keys().collect::<Vec<_>>(),
            ["etc/", "pause"],
            "sorted layer entries"
        );
        for (header, _) in layer.values() {
            assert_eq!(
                (header.uid().unwrap(), header.gid().unwrap(), header.mtime().unwrap()),
                (0, 0, 42)
            );
        }
        assert_eq!(layer["pause"].0.mode().unwrap(), 0o755);
    }

    #[test]
    fn requires_the_entrypoint() {
        let empty = tempfile::tempdir().unwrap();
        assert!(archive(empty.path(), &spec(), "1", 0).is_err());
    }
}

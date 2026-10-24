//! The system images shipped in the root filesystem (the pod sandbox's pause), imported at boot.
//!
//! Each is an OCI image layout archived as a tar file, its reference in the
//! `io.containerd.image.name` annotation of `index.json`. CRI cannot import images, so this is
//! the one use of containerd's native API: the transfer service imports the archive, streamed
//! through the streaming service, into the CRI namespace and unpacks it.
//!
//! Streaming protocol (containerd `core/transfer/streaming`): the client opens
//! `Streaming.Stream` and sends `StreamInit{id}`; containerd acks with `google.protobuf.Empty`.
//! `Transfer` then gets an `ImageImportStream{stream: id}` source. While importing, containerd
//! sends `WindowUpdate`s granting bytes; the client sends `Data` chunks within the window, then
//! half-closes the stream at the end of the archive.

use std::collections::{BTreeMap, HashMap};
use std::ops::Range;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use containerd_api::containerd::services::snapshots::v1::{StatSnapshotRequest, snapshots_client::SnapshotsClient};
use containerd_api::containerd::services::streaming::v1::{StreamInit, streaming_client::StreamingClient};
use containerd_api::containerd::services::transfer::v1::{TransferRequest, transfer_client::TransferClient};
use containerd_api::containerd::types::Platform;
use containerd_api::containerd::types::transfer::{
    Data, ImageImportStream, ImageReference, ImageStore, UnpackConfiguration, WindowUpdate,
};
use containerd_api::{Any, request, to_any};
use oci_spec::image::{ImageConfiguration, ImageIndex, ImageManifest};
use prost::{Message as _, Name as _};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Code;
use tonic::codec::Streaming;
use tonic::transport::Channel;

use super::cri::Cri;
use crate::types::{Digest, ImageRef};

/// Where the archives are, in the root filesystem.
pub const DIR: &str = "/usr/share/hardened/images";
/// The containerd namespace of CRI.
const NAMESPACE: &str = "k8s.io";
const SNAPSHOTTER: &str = "overlayfs";
const OS: &str = "linux";
const ARCHITECTURE: &str = "amd64";
const IMAGE_NAME_ANNOTATION: &str = "io.containerd.image.name";
/// Labels of the images CRI pulls itself, plus pinning: bundled images are never collected.
const LABELS: &[(&str, &str)] = &[
    ("io.cri-containerd.image", "managed"),
    ("io.cri-containerd.pinned", "pinned"),
];
/// Bounds the archives read into memory (they hold a few small layers).
const MAX_ARCHIVE: u64 = 256 << 20;
/// containerd's chunk size.
const MAX_CHUNK: usize = 32 << 10;
/// How long CRI may take to see an imported image (it follows the image store's events).
const VISIBLE_TIMEOUT: Duration = Duration::from_secs(10);
const VISIBLE_POLL: Duration = Duration::from_millis(100);

/// What an archive holds, from its `index.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundledImage {
    pub reference: ImageRef,
    /// The image's ID for CRI.
    pub config: Digest,
    /// The key of its unpacked snapshot.
    pub chain_id: Digest,
}

/// An image archive, read into memory.
pub struct Archive {
    pub image: BundledImage,
    data: Vec<u8>,
}

/// The archives of `dir`, by file name. A missing directory holds none.
pub async fn archives(dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("reading {}", dir.display())),
    };
    let mut paths = Vec::new();
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "tar") {
            paths.push(path);
        }
    }
    paths.sort();
    Ok(paths)
}

impl Archive {
    pub async fn read(path: &Path) -> anyhow::Result<Self> {
        let len = tokio::fs::metadata(path).await?.len();
        ensure!(len <= MAX_ARCHIVE, "{} is too large ({len} bytes)", path.display());
        let data = tokio::fs::read(path).await?;
        let image = inspect(&data).with_context(|| format!("reading {}", path.display()))?;
        Ok(Self { image, data })
    }
}

/// Reads the reference, configuration digest and chain ID of an image archive, verifying the
/// manifest and configuration against their digests.
pub fn inspect(archive: &[u8]) -> anyhow::Result<BundledImage> {
    let files = index_files(archive)?;
    let file = |name: &str| -> anyhow::Result<&[u8]> {
        let range = files.get(name).with_context(|| format!("the archive has no {name}"))?;
        Ok(&archive[range.clone()])
    };
    let blob = |digest: &str| -> anyhow::Result<&[u8]> {
        let expected: Digest = digest.parse()?;
        let hex = digest.trim_start_matches("sha256:");
        let blob = file(&format!("blobs/sha256/{hex}"))?;
        let actual = Digest::of(blob);
        ensure!(actual == expected, "blob {expected} has digest {actual}");
        Ok(blob)
    };

    let index = ImageIndex::from_reader(file("index.json")?).context("parsing index.json")?;
    let [manifest] = index.manifests().as_slice() else {
        bail!("index.json must list exactly one manifest");
    };
    let name = manifest
        .annotations()
        .as_ref()
        .and_then(|a| a.get(IMAGE_NAME_ANNOTATION))
        .with_context(|| format!("the manifest has no {IMAGE_NAME_ANNOTATION} annotation"))?;
    let reference: ImageRef = name.parse()?;
    // The image is stored under the annotated name: a normalized name must not differ from it.
    ensure!(
        reference.as_str() == name,
        "{name} is not a normalized reference ({reference})"
    );

    let manifest = ImageManifest::from_reader(blob(manifest.digest().as_ref())?).context("parsing the manifest")?;
    let config_digest = manifest.config().digest().to_string();
    let config = ImageConfiguration::from_reader(blob(&config_digest)?).context("parsing the configuration")?;
    let diff_ids = config
        .rootfs()
        .diff_ids()
        .iter()
        .map(|id| id.parse::<Digest>())
        .collect::<Result<Vec<_>, _>>()
        .context("invalid layer diff ID")?;
    Ok(BundledImage {
        reference,
        config: config_digest.parse()?,
        chain_id: Digest::chain_id(&diff_ids).context("the image has no layers")?,
    })
}

/// The regular files of a tar archive and where their contents are.
fn index_files(archive: &[u8]) -> anyhow::Result<BTreeMap<String, Range<usize>>> {
    let mut files = BTreeMap::new();
    for entry in tar::Archive::new(archive).entries()? {
        let entry = entry?;
        if !entry.header().entry_type().is_file() {
            continue;
        }
        let path = entry.path()?;
        let name = path.to_string_lossy();
        let name = name.trim_start_matches("./").to_owned();
        let start = usize::try_from(entry.raw_file_position())?;
        let len = usize::try_from(entry.size())?;
        let end = start.checked_add(len).filter(|&end| end <= archive.len());
        files.insert(name, start..end.context("truncated archive")?);
    }
    Ok(files)
}

/// What [`import`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Imported {
    /// Present and unpacked since an earlier boot.
    AlreadyPresent,
    Imported,
}

/// Imports an archive into CRI's image store and unpacks it, unless already done.
pub async fn import(channel: &Channel, cri: &Cri, archive: Archive) -> anyhow::Result<Imported> {
    let image = archive.image.clone();
    if is_present(channel, cri, &image).await? {
        return Ok(Imported::AlreadyPresent);
    }
    transfer(channel, &image.reference, archive.data).await?;

    // CRI learns about the image from the image store's events.
    let deadline = tokio::time::Instant::now() + VISIBLE_TIMEOUT;
    loop {
        let id = cri.image_id(&image.reference).await?;
        match id {
            Some(id) if id.as_str() == image.config.to_string() => return Ok(Imported::Imported),
            _ if tokio::time::Instant::now() >= deadline => {
                let found = id.map_or_else(|| "nothing".to_owned(), |id| id.to_string());
                bail!(
                    "after the import, {} resolves to {found}, not {}",
                    image.reference,
                    image.config
                );
            }
            _ => tokio::time::sleep(VISIBLE_POLL).await,
        }
    }
}

/// Whether CRI resolves the reference to this image and its snapshot exists (CRI does not check
/// that the image is unpacked).
async fn is_present(channel: &Channel, cri: &Cri, image: &BundledImage) -> anyhow::Result<bool> {
    let id = cri.image_id(&image.reference).await?;
    if id.is_none_or(|id| id.as_str() != image.config.to_string()) {
        return Ok(false);
    }
    let stat = SnapshotsClient::new(channel.clone())
        .stat(request(
            NAMESPACE,
            StatSnapshotRequest {
                snapshotter: SNAPSHOTTER.into(),
                key: image.chain_id.to_string(),
            },
        ))
        .await;
    match stat {
        Ok(_) => Ok(true),
        Err(status) if status.code() == Code::NotFound => Ok(false),
        Err(status) => Err(status).context("checking the image's snapshot"),
    }
}

/// Streams `archive` to the transfer service, storing the image as `reference`.
async fn transfer(channel: &Channel, reference: &ImageRef, archive: Vec<u8>) -> anyhow::Result<()> {
    let id = format!("import-{}", uuid::Uuid::new_v4());
    let (tx, rx) = mpsc::channel(4);
    tx.send(to_any(&StreamInit { id: id.clone() })).await?;
    let mut responses = StreamingClient::new(channel.clone())
        .stream(request(NAMESPACE, ReceiverStream::new(rx)))
        .await
        .context("opening the import stream")?
        .into_inner();
    // The ack: the stream is registered and can be named in the transfer.
    responses
        .message()
        .await
        .context("opening the import stream")?
        .context("containerd closed the import stream")?;

    let sender = tokio::spawn(send(archive, tx, responses));
    let transfer = TransferRequest {
        source: Some(to_any(&ImageImportStream {
            stream: id,
            // Detected by containerd (an uncompressed tar).
            media_type: String::new(),
            force_compress: false,
        })),
        destination: Some(to_any(&image_store(reference))),
        options: None,
    };
    let result = TransferClient::new(channel.clone())
        .transfer(request(NAMESPACE, transfer))
        .await;
    // The import read the whole archive (or failed): the sender has nothing left to do.
    let send_error = if sender.is_finished() {
        sender.await.ok().and_then(Result::err)
    } else {
        sender.abort();
        None
    };
    match (result, send_error) {
        (Ok(_), _) => Ok(()),
        (Err(status), Some(e)) => Err(e.context(status.message().to_owned())).context("importing"),
        (Err(status), None) => Err(status).context("importing"),
    }
}

/// The destination of the import: the annotated name only, unpacked for linux/amd64.
fn image_store(reference: &ImageRef) -> ImageStore {
    let platform = Platform {
        os: OS.into(),
        architecture: ARCHITECTURE.into(),
        ..Default::default()
    };
    ImageStore {
        // Images are named from the manifests' annotations: a prefix reference matching only
        // the full name stores it, nothing else.
        name: String::new(),
        labels: LABELS
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect::<HashMap<_, _>>(),
        platforms: vec![platform.clone()],
        extra_references: vec![ImageReference {
            name: reference.to_string(),
            is_prefix: true,
            ..Default::default()
        }],
        unpacks: vec![UnpackConfiguration {
            platform: Some(platform),
            snapshotter: SNAPSHOTTER.into(),
        }],
        ..Default::default()
    }
}

/// Sends the archive within the windows containerd grants, then half-closes the stream.
async fn send(archive: Vec<u8>, tx: mpsc::Sender<Any>, mut responses: Streaming<Any>) -> anyhow::Result<()> {
    let mut sent = 0;
    let mut window = 0;
    while sent < archive.len() {
        if window == 0 {
            let message = responses
                .message()
                .await?
                .context("containerd closed the import stream early")?;
            window = window_update(&message)?;
            continue;
        }
        let len = (archive.len() - sent).min(window).min(MAX_CHUNK);
        let data = Data {
            data: archive[sent..sent + len].to_vec(),
        };
        tx.send(to_any(&data))
            .await
            .context("containerd closed the import stream early")?;
        sent += len;
        window -= len;
    }
    // End of the archive: containerd's reader sees EOF, then ends the stream.
    drop(tx);
    while responses.message().await?.is_some() {}
    Ok(())
}

/// The bytes granted by a `WindowUpdate`.
fn window_update(message: &Any) -> anyhow::Result<usize> {
    let name = message.type_url.rsplit('/').next().unwrap_or_default();
    ensure!(
        name == WindowUpdate::full_name(),
        "unexpected {} on the import stream",
        message.type_url
    );
    let update = WindowUpdate::decode(message.value.as_slice())?;
    Ok(usize::try_from(update.update).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// A tar entry, as the `tar` crate writes it.
    fn add(builder: &mut tar::Builder<Vec<u8>>, path: &str, data: &[u8]) {
        let mut header = tar::Header::new_ustar();
        header.set_size(data.len() as u64);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        builder.append_data(&mut header, path, data).unwrap();
    }

    fn descriptor(media_type: &str, blob: &[u8]) -> serde_json::Value {
        json!({ "mediaType": media_type, "digest": Digest::of(blob).to_string(), "size": blob.len() })
    }

    /// An archive as dust-builder writes it (`crates/dust-builder/src/oci.rs`).
    fn archive(name: &str, tamper: bool) -> (Vec<u8>, Digest, Digest) {
        let layer = b"layer".to_vec();
        let diff_id = Digest::of(&layer);
        let config = serde_json::to_vec(&json!({
            "architecture": "amd64",
            "os": "linux",
            "config": { "Entrypoint": ["/pause"], "User": "65534:65534" },
            "rootfs": { "type": "layers", "diff_ids": [diff_id.to_string()] },
        }))
        .unwrap();
        let manifest = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": descriptor("application/vnd.oci.image.config.v1+json", &config),
            "layers": [descriptor("application/vnd.oci.image.layer.v1.tar", &layer)],
        }))
        .unwrap();
        let mut manifest_descriptor = descriptor("application/vnd.oci.image.manifest.v1+json", &manifest);
        manifest_descriptor["annotations"] = json!({
            "io.containerd.image.name": name,
            "org.opencontainers.image.ref.name": "1.0",
        });
        let index = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [manifest_descriptor],
        }))
        .unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        add(&mut builder, "oci-layout", br#"{"imageLayoutVersion":"1.0.0"}"#);
        add(&mut builder, "index.json", &index);
        for blob in [&config, &manifest, &layer] {
            let hex = Digest::of(blob).to_string().trim_start_matches("sha256:").to_owned();
            let data = if tamper && blob == &manifest {
                b"tampered".to_vec()
            } else {
                blob.clone()
            };
            add(&mut builder, &format!("blobs/sha256/{hex}"), &data);
        }
        (builder.into_inner().unwrap(), Digest::of(&config), diff_id)
    }

    #[test]
    fn reads_the_annotated_reference() {
        let (data, config, diff_id) = archive("localhost/hardened/pause:1.0", false);
        let image = inspect(&data).unwrap();
        assert_eq!(image.reference.as_str(), "localhost/hardened/pause:1.0");
        assert_eq!(image.config, config);
        // A single layer's chain ID is its diff ID.
        assert_eq!(image.chain_id, diff_id);
    }

    #[test]
    fn rejects_invalid_archives() {
        let (data, ..) = archive("localhost/hardened/pause:1.0", true);
        assert!(inspect(&data).is_err(), "tampered manifest");
        let (data, ..) = archive("pause", false);
        assert!(inspect(&data).is_err(), "unnormalized reference");
        assert!(inspect(b"not a tar").is_err());
    }

    #[test]
    fn stores_only_the_annotated_name_unpacked() {
        let store = image_store(&"localhost/hardened/pause:3.10".parse().unwrap());
        assert!(store.name.is_empty());
        let [reference] = store.extra_references.as_slice() else {
            panic!("one reference expected");
        };
        assert_eq!(reference.name, "localhost/hardened/pause:3.10");
        assert!(reference.is_prefix && !reference.allow_overwrite && !reference.add_digest);
        assert_eq!(store.labels["io.cri-containerd.pinned"], "pinned");
        let unpack = &store.unpacks[0];
        assert_eq!(unpack.snapshotter, "overlayfs");
        let platform = unpack.platform.as_ref().unwrap();
        assert_eq!(
            (platform.os.as_str(), platform.architecture.as_str()),
            ("linux", "amd64")
        );
    }

    #[test]
    fn uses_containerd_type_urls() {
        let source = to_any(&ImageImportStream::default());
        assert_eq!(source.type_url, "containerd.types.transfer.ImageImportStream");
        assert_eq!(
            to_any(&StreamInit::default()).type_url,
            "containerd.services.streaming.v1.StreamInit"
        );
        assert_eq!(to_any(&Data::default()).type_url, "containerd.types.transfer.Data");

        let update = to_any(&WindowUpdate { update: 65536 });
        assert_eq!(window_update(&update).unwrap(), 65536);
        let prefixed = Any {
            type_url: "types.googleapis.com/containerd.types.transfer.WindowUpdate".into(),
            ..update
        };
        assert_eq!(window_update(&prefixed).unwrap(), 65536);
        assert!(window_update(&to_any(&Data::default())).is_err());
    }

    #[tokio::test]
    async fn lists_archives() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["pause.tar", "extra.tar", "README"] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        let names: Vec<_> = archives(dir.path())
            .await
            .unwrap()
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, ["extra.tar", "pause.tar"]);
        assert!(archives(&dir.path().join("missing")).await.unwrap().is_empty());
    }
}

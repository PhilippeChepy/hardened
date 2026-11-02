//! What the update probes download: pages, release metadata and files, over HTTPS.

use std::fs::File;
use std::io;
use std::path::Path;

use anyhow::Context;

use crate::sha256::Sha256;

/// The largest page or metadata document read (a large directory listing, a repository's refs).
const LIMIT: u64 = 64 << 20;

/// A status that is an answer, not a failure: there is no such file.
#[derive(Debug, thiserror::Error)]
#[error("{0}: not found")]
pub struct NotFound(pub String);

/// The body of `url`, as text.
///
/// # Errors
///
/// [`NotFound`] on a 404 (or 410), another error on any other failure.
pub fn text(url: &str) -> anyhow::Result<String> {
    let mut response = get(url)?;
    (response
        .body_mut()
        .with_config()
        .limit(LIMIT)
        .read_to_string())
    .with_context(|| url.to_owned())
}

/// The body of `url`, as bytes.
///
/// # Errors
///
/// As [`text`].
pub fn bytes(url: &str) -> anyhow::Result<Vec<u8>> {
    let mut response = get(url)?;
    (response.body_mut().with_config().limit(LIMIT).read_to_vec()).with_context(|| url.to_owned())
}

/// Downloads `url` to `path`, returning its checksum.
///
/// # Errors
///
/// As [`text`], or when `path` cannot be written.
pub fn download(url: &str, path: &Path) -> anyhow::Result<Sha256> {
    let mut reader = get(url)?.into_body().into_reader();
    let mut file = File::create(path).with_context(|| path.display().to_string())?;
    io::copy(&mut reader, &mut file).with_context(|| url.to_owned())?;
    file.sync_all()?;
    Ok(Sha256::of_file(path)?)
}

/// How many times a request is tried: servers stall or drop connections now and then.
const ATTEMPTS: u32 = 3;

fn get(url: &str) -> anyhow::Result<ureq::http::Response<ureq::Body>> {
    let mut attempt = 1;
    loop {
        match crate::http_agent::agent().get(url).call() {
            Ok(response) => return Ok(response),
            Err(ureq::Error::StatusCode(404 | 410)) => return Err(NotFound(url.to_owned()).into()),
            Err(e) if attempt == ATTEMPTS => return Err(e).with_context(|| url.to_owned()),
            Err(e) => eprintln!("==> {url}: {e}, trying again"),
        }
        std::thread::sleep(std::time::Duration::from_secs(5 << attempt));
        attempt += 1;
    }
}

/// Whether `error` is a [`NotFound`].
#[must_use]
pub fn is_not_found(error: &anyhow::Error) -> bool {
    error.downcast_ref::<NotFound>().is_some()
}

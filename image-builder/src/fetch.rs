//! Source archive download and verification.

use std::fs::File;
use std::io;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};

use crate::Paths;
use crate::recipe::{Recipe, Source};
use crate::sha256::Sha256;

/// How many times a download is tried: servers stall or drop connections now and then.
const ATTEMPTS: u32 = 4;

pub fn fetch_all<'a>(
    paths: &Paths,
    recipes: impl IntoIterator<Item = &'a Recipe>,
) -> anyhow::Result<()> {
    let dir = paths.sources();
    std::fs::create_dir_all(&dir)?;
    for recipe in recipes {
        for source in &recipe.plan.sources {
            fetch(&dir, source).with_context(|| format!("{}: {}", recipe.name(), source.url))?;
        }
    }
    Ok(())
}

fn fetch(dir: &Path, source: &Source) -> anyhow::Result<()> {
    let path = dir.join(source.sha256.to_string());
    if path.exists() {
        let actual = Sha256::of_file(&path)?;
        if actual == source.sha256 {
            return Ok(());
        }
        eprintln!(
            "==> {}: cached file has checksum {actual}, downloading again",
            path.display()
        );
    }

    eprintln!("==> fetching {}", source.url);
    let partial = path.with_extension("part");
    let mut attempt = 1;
    while let Err(error) = download(&source.url, &partial) {
        if attempt == ATTEMPTS {
            return Err(error.context(format!("{ATTEMPTS} attempts")));
        }
        eprintln!("==> {}: {error:#}, trying again", source.url);
        std::thread::sleep(Duration::from_secs(5 << attempt));
        attempt += 1;
    }

    let actual = Sha256::of_file(&partial)?;
    if actual != source.sha256 {
        std::fs::remove_file(&partial)?;
        bail!(
            "checksum mismatch: expected {}, got {actual}",
            source.sha256
        );
    }
    std::fs::rename(partial, path)?;
    Ok(())
}

/// Downloads `url` to `path`, from the start.
fn download(url: &str, path: &Path) -> anyhow::Result<()> {
    let mut response = crate::http_agent::agent()
        .get(url)
        .call()?
        .into_body()
        .into_reader();
    let mut file = File::create(path)?;
    io::copy(&mut response, &mut file)?;
    file.sync_all()?;
    Ok(())
}

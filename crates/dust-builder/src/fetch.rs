//! Source archive download and verification.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use anyhow::{Context, bail};
use sha2::Digest;

use crate::Paths;
use crate::recipe::{Recipe, Source};
use crate::sha256::Sha256;

pub fn fetch_all<'a>(paths: &Paths, recipes: impl IntoIterator<Item = &'a Recipe>) -> anyhow::Result<()> {
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
    let file_name = source.file_name().map_err(anyhow::Error::msg)?;
    let path = dir.join(file_name);
    if path.exists() {
        let actual = Sha256::of_file(&path)?;
        if actual == source.sha256 {
            return Ok(());
        }
        eprintln!(
            "==> {}: cached file has checksum {actual}, downloading again",
            file_name
        );
    }

    eprintln!("==> fetching {}", source.url);
    let partial = path.with_extension("part");
    let mut response = ureq::get(source.url).call()?.into_body().into_reader();
    let mut file = File::create(&partial)?;
    let mut hasher = sha2::Sha256::new();
    let mut buf = vec![0; 1 << 16];
    loop {
        let n = response.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        file.write_all(&buf[..n])?;
    }
    file.sync_all()?;

    let actual = Sha256::finalize(hasher);
    if actual != source.sha256 {
        std::fs::remove_file(&partial)?;
        bail!("checksum mismatch: expected {}, got {actual}", source.sha256);
    }
    std::fs::rename(partial, path)?;
    Ok(())
}

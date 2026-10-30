//! Source archive download and verification.

use std::fs::File;
use std::io;
use std::path::Path;

use anyhow::{Context, bail};

use crate::Paths;
use crate::recipe::{Recipe, Source};
use crate::sha256::Sha256;

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
    let mut response = ureq::get(&source.url).call()?.into_body().into_reader();
    let mut file = File::create(&partial)?;
    io::copy(&mut response, &mut file)?;
    file.sync_all()?;

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

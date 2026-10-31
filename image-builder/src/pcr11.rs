//! The PCR 11 a UKI's systemd-stub measures, which a verifier of the machine's attestation
//! expects: SHA-256, from zero, extended with the hash of each UKI section's name (with its NUL)
//! then of its contents as loaded (its virtual size, zero-padded), in systemd's order
//! (`unified_sections` of `src/fundamental/uki.c`), but `.pcrsig`. Nothing else extends PCR 11:
//! the image has no systemd to measure its boot phases.

use anyhow::{Context as _, bail};
use sha2::Digest as _;

use crate::sha256::Sha256;

/// systemd 262's measured sections, in order.
const SECTIONS: [&str; 14] = [
    ".linux", ".osrel", ".cmdline", ".initrd", ".ucode", ".splash", ".dtb", ".uname", ".sbat",
    ".pcrpkey", ".profile", ".dtbauto", ".hwids", ".efifw",
];

/// The PCR 11 (SHA-256 bank) booting `uki` gives.
pub fn expected(uki: &[u8]) -> anyhow::Result<Sha256> {
    let sections = sections(uki)?;
    let mut pcr = [0; 32];
    for name in SECTIONS {
        let Some(contents) = sections
            .iter()
            .find(|(found, _)| found == name)
            .map(|(_, c)| c)
        else {
            continue;
        };
        let name = [name.as_bytes(), &[0]].concat();
        for measured in [&name[..], contents] {
            pcr = sha2::Sha256::new()
                .chain_update(pcr)
                .chain_update(sha2::Sha256::digest(measured))
                .finalize()
                .into();
        }
    }
    Ok(Sha256::from_bytes(pcr))
}

/// The sections of the PE image `pe`: their names and contents as loaded.
fn sections(pe: &[u8]) -> anyhow::Result<Vec<(String, Vec<u8>)>> {
    let u16_at = |at: usize| -> anyhow::Result<usize> {
        let bytes = pe.get(at..at + 2).context("truncated PE image")?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]).into())
    };
    let u32_at = |at: usize| -> anyhow::Result<usize> {
        let bytes = pe.get(at..at + 4).context("truncated PE image")?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize)
    };
    let header = u32_at(0x3c)?;
    if pe.get(header..header + 4) != Some(b"PE\0\0") {
        bail!("not a PE image");
    }
    let count = u16_at(header + 6)?;
    let table = header + 24 + u16_at(header + 20)?;
    (0..count)
        .map(|index| {
            let entry = table + 40 * index;
            let name = pe
                .get(entry..entry + 8)
                .context("truncated section table")?;
            let name = String::from_utf8_lossy(name)
                .trim_end_matches('\0')
                .to_owned();
            let (virtual_size, raw_size, raw_at) =
                (u32_at(entry + 8)?, u32_at(entry + 16)?, u32_at(entry + 20)?);
            let stored = raw_size.min(virtual_size);
            let mut contents = pe
                .get(raw_at..raw_at + stored)
                .with_context(|| format!("section {name} past the end of the image"))?
                .to_vec();
            contents.resize(virtual_size, 0);
            Ok((name, contents))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A PE image of `sections` (name, contents, virtual size).
    fn pe(sections: &[(&str, &[u8], u32)]) -> Vec<u8> {
        let header = 0x40;
        let table = header + 24;
        let mut image = vec![0; table + 40 * sections.len()];
        image[0x3c..0x40].copy_from_slice(&(header as u32).to_le_bytes());
        image[header..header + 4].copy_from_slice(b"PE\0\0");
        image[header + 6..header + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        for (index, (name, contents, virtual_size)) in sections.iter().enumerate() {
            let entry = table + 40 * index;
            image[entry..entry + name.len()].copy_from_slice(name.as_bytes());
            image[entry + 8..entry + 12].copy_from_slice(&virtual_size.to_le_bytes());
            let at = image.len() as u32;
            image[entry + 16..entry + 20].copy_from_slice(&(contents.len() as u32).to_le_bytes());
            image[entry + 20..entry + 24].copy_from_slice(&at.to_le_bytes());
            image.extend_from_slice(contents);
        }
        image
    }

    fn extend(pcr: [u8; 32], measured: &[u8]) -> [u8; 32] {
        sha2::Sha256::new()
            .chain_update(pcr)
            .chain_update(sha2::Sha256::digest(measured))
            .finalize()
            .into()
    }

    #[test]
    fn measures_the_uki_sections_in_systemd_order() {
        // In file order: the stub's own code first, the signature not measured.
        let uki = pe(&[
            (".text", b"stub", 4),
            (".cmdline", b"ro", 2),
            (".pcrsig", b"{}", 2),
            (".linux", b"kernel", 8),
        ]);
        let mut pcr = [0; 32];
        for measured in [&b".linux\0"[..], b"kernel\0\0", b".cmdline\0", b"ro"] {
            pcr = extend(pcr, measured);
        }
        assert_eq!(expected(&uki).unwrap(), Sha256::from_bytes(pcr));
    }

    #[test]
    fn rejects_what_is_not_a_pe_image() {
        assert!(expected(b"MZ").is_err());
        assert!(expected(&[0; 0x80]).is_err());
    }
}

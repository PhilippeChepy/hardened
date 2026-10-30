//! User-data transport encodings: platforms limit its size (a few tens of KiB), so it is often
//! gzipped, and base64-encoded where only text is accepted. Detected: TOML, gzip(TOML),
//! base64(TOML) and base64(gzip(TOML)).

use std::io::Read;

use controllers_helpers::base64_text;
use flate2::read::GzDecoder;

use crate::settings::Error;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// Against gzip bombs.
pub(super) const MAX_DECODED: u64 = 4 << 20;

/// The TOML text of user-data, whatever its encoding.
pub(super) fn decode(raw: &[u8]) -> Result<String, Error> {
    let trimmed = raw.trim_ascii();
    if trimmed.starts_with(&GZIP_MAGIC) {
        return utf8(gunzip(trimmed)?);
    }
    // TOML is seldom valid base64 (`=`, `[`, spaces, quotes); what decodes to non-UTF-8 is taken
    // as plain text.
    if let Some(bytes) = base64_text::decode(trimmed) {
        if bytes.starts_with(&GZIP_MAGIC) {
            return utf8(gunzip(&bytes)?);
        }
        if let Ok(text) = String::from_utf8(bytes) {
            return Ok(text);
        }
    }
    utf8(raw.to_vec())
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    GzDecoder::new(bytes)
        .take(MAX_DECODED + 1)
        .read_to_end(&mut out)
        .map_err(Error::Gzip)?;
    if out.len() as u64 > MAX_DECODED {
        return Err(Error::TooLarge);
    }
    Ok(out)
}

fn utf8(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| Error::NotUtf8)
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use flate2::Compression;
    use flate2::write::GzEncoder;

    use super::*;

    const DOCUMENT: &str = "[settings.network]\nhostname = \"a\"\n";

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn base64(data: &[u8]) -> Vec<u8> {
        base64_text::encode(data).into_bytes()
    }

    #[test]
    fn decodes_all_encodings() {
        assert_eq!(decode(DOCUMENT.as_bytes()).unwrap(), DOCUMENT);
        assert_eq!(decode(&gzip(DOCUMENT.as_bytes())).unwrap(), DOCUMENT);
        assert_eq!(decode(&base64(DOCUMENT.as_bytes())).unwrap(), DOCUMENT);
        assert_eq!(
            decode(&base64(&gzip(DOCUMENT.as_bytes()))).unwrap(),
            DOCUMENT
        );
    }

    #[test]
    fn wrapped_base64_is_accepted() {
        let mut wrapped = base64(DOCUMENT.as_bytes());
        wrapped.insert(8, b'\n');
        assert_eq!(decode(&wrapped).unwrap(), DOCUMENT);
    }

    #[test]
    fn rejects_gzip_bombs() {
        let size = usize::try_from(MAX_DECODED + 1).expect("4 MiB fits in usize");
        let bomb = gzip(&vec![b'a'; size]);
        assert!(decode(&bomb).is_err());
    }
}

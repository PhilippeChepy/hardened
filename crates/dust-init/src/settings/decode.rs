//! User-data transport encodings.
//!
//! Platforms impose size limits on user-data (a few tens of KiB), so it is commonly gzipped and,
//! where the platform only accepts text, base64-encoded. Accepted forms, detected automatically:
//! plain TOML, gzip(TOML), base64(TOML) and base64(gzip(TOML)).

use std::io::Read;

use flate2::read::GzDecoder;

use super::Error;

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];
/// Upper bound for decompressed user-data, protecting PID 1 against gzip bombs.
const MAX_DECODED: u64 = 4 << 20;

/// Decodes raw user-data into TOML text.
pub fn decode(raw: &[u8]) -> Result<String, Error> {
    let trimmed = raw.trim_ascii();
    if trimmed.starts_with(&GZIP_MAGIC) {
        return utf8(gunzip(trimmed)?);
    }
    if let Some(bytes) = base64_payload(trimmed) {
        if bytes.starts_with(&GZIP_MAGIC) {
            return utf8(gunzip(&bytes)?);
        }
        if let Ok(text) = String::from_utf8(bytes) {
            return Ok(text);
        }
    }
    utf8(raw.to_vec())
}

/// Returns the decoded bytes if `raw` is entirely standard base64 (line breaks allowed).
///
/// TOML documents are rarely valid base64 (`=`, `[`, spaces, quotes...), and ambiguous inputs that
/// decode to non-UTF-8 fall back to being treated as plain text.
fn base64_payload(raw: &[u8]) -> Option<Vec<u8>> {
    if raw.iter().all(u8::is_ascii_whitespace) {
        return None;
    }
    crate::types::decode_base64(raw)
}

fn gunzip(bytes: &[u8]) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    GzDecoder::new(bytes)
        .take(MAX_DECODED + 1)
        .read_to_end(&mut out)
        .map_err(|e| Error::Encoding(format!("gzip: {e}")))?;
    if out.len() as u64 > MAX_DECODED {
        return Err(Error::Encoding(format!(
            "decompressed user-data exceeds {MAX_DECODED} bytes"
        )));
    }
    Ok(out)
}

fn utf8(bytes: Vec<u8>) -> Result<String, Error> {
    String::from_utf8(bytes).map_err(|_| Error::Encoding("user-data is not valid UTF-8".into()))
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use base64::Engine;
    use flate2::{Compression, write::GzEncoder};

    use super::decode;

    const DOC: &str = "[settings.network]\nhostname = \"a\"\n";

    fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(data).unwrap();
        encoder.finish().unwrap()
    }

    fn b64(data: &[u8]) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.encode(data).into_bytes()
    }

    #[test]
    fn decodes_all_encodings() {
        assert_eq!(decode(DOC.as_bytes()).unwrap(), DOC);
        assert_eq!(decode(&gzip(DOC.as_bytes())).unwrap(), DOC);
        assert_eq!(decode(&b64(DOC.as_bytes())).unwrap(), DOC);
        assert_eq!(decode(&b64(&gzip(DOC.as_bytes()))).unwrap(), DOC);
    }

    #[test]
    fn wrapped_base64_is_accepted() {
        let mut wrapped = b64(DOC.as_bytes());
        wrapped.insert(8, b'\n');
        assert_eq!(decode(&wrapped).unwrap(), DOC);
    }

    #[test]
    fn rejects_gzip_bombs() {
        let bomb = gzip(&vec![b'a'; (super::MAX_DECODED + 1) as usize]);
        assert!(decode(&bomb).is_err());
    }
}

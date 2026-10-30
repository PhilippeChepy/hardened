//! Base64, in which settings hold binary and PEM values.

use base64::Engine;
use base64::engine::general_purpose;

use crate::InvalidValue;

/// Decodes standard base64, ignoring whitespace (line breaks of `base64` output included).
#[must_use]
pub fn decode(text: &[u8]) -> Option<Vec<u8>> {
    let compact: Vec<u8> = text
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    general_purpose::STANDARD.decode(compact).ok()
}

/// Encodes to standard base64.
#[must_use]
pub fn encode(data: impl AsRef<[u8]>) -> String {
    general_purpose::STANDARD.encode(data)
}

/// The PEM text of a base64-encoded settings value (Bottlerocket encodes PEM that way).
pub(crate) fn pem_from_base64(kind: &'static str, encoded: &str) -> Result<String, InvalidValue> {
    let bytes = decode(encoded.as_bytes())
        .ok_or_else(|| InvalidValue::new(kind, "<base64>", "is not base64"))?;
    String::from_utf8(bytes)
        .map_err(|_| InvalidValue::new(kind, "<base64>", "does not decode to PEM text"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_ignores_line_breaks() {
        let encoded = encode("a longer text, wrapped by base64 at 76 columns");
        let wrapped = format!("{}\n{}\n", &encoded[..10], &encoded[10..]);
        assert_eq!(
            decode(wrapped.as_bytes()).unwrap(),
            b"a longer text, wrapped by base64 at 76 columns"
        );
        assert_eq!(decode(b"!!"), None);
    }
}

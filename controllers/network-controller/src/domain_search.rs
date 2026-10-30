//! The domain search list of option 119 (RFC 3397): a sequence of domain names in DNS wire format
//! (RFC 1035 §3.1), compressed with pointers whose offsets count from the start of the option's
//! (concatenated) value.

use controllers_helpers::DomainName;

/// The longest name in wire format: its labels with their length bytes, and the root's (RFC 1035
/// §2.3.4).
const MAX_NAME_LEN: usize = 255;

/// The two high bits of a pointer's first byte.
const POINTER: u8 = 0b1100_0000;

/// The names of `value`, dotted, without the trailing dot (the root name is empty); `None` if a
/// name is malformed: truncated, too long, with a reserved label type, or with a pointer that
/// does not point strictly before the previous one (which also rules out loops).
#[must_use]
pub fn decode(value: &[u8]) -> Option<Vec<String>> {
    let mut names = Vec::new();
    let mut at = 0;
    while at < value.len() {
        let (name, next) = decode_name(value, at)?;
        names.push(name);
        at = next;
    }
    Some(names)
}

/// The name starting at `start`, and where the next one starts.
#[must_use]
fn decode_name(value: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels: Vec<&str> = Vec::new();
    let mut wire_len = 0;
    let mut at = start;
    // Where the name ends in the sequence, set at its terminator or first pointer.
    let mut next = None;
    // Pointers must point strictly before this.
    let mut limit = start;
    loop {
        let len = *value.get(at)?;
        if len & POINTER == POINTER {
            let low = *value.get(at.checked_add(1)?)?;
            let target = (usize::from(len & !POINTER) << 8) | usize::from(low);
            next.get_or_insert(at + 2);
            if target >= limit {
                return None;
            }
            limit = target;
            at = target;
        } else if len & POINTER != 0 {
            // 0b01 and 0b10 are reserved (extended label types, RFC 6891).
            return None;
        } else {
            wire_len += 1 + usize::from(len);
            if wire_len > MAX_NAME_LEN {
                return None;
            }
            if len == 0 {
                next.get_or_insert(at + 1);
                break;
            }
            let label = value.get(at + 1..at + 1 + usize::from(len))?;
            labels.push(str::from_utf8(label).ok()?);
            at += 1 + usize::from(len);
        }
    }
    Some((labels.join("."), next?))
}

/// `names` in wire format, uncompressed.
#[must_use]
pub fn encode(names: &[DomainName]) -> Vec<u8> {
    let mut value = Vec::new();
    for name in names {
        for label in name.as_str().split('.') {
            // A domain name's labels are 1 to 63 bytes long.
            value.push(u8::try_from(label.len()).expect("labels are at most 63 bytes"));
            value.extend_from_slice(label.as_bytes());
        }
        value.push(0);
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes() {
        let cases: &[(&[u8], &[&str])] = &[
            (b"", &[]),
            (b"\x00", &[""]),
            (b"\x07example\x03com\x00", &["example.com"]),
            // RFC 3397 §2's example: eng.apple.com and marketing.apple.com.
            (
                b"\x03eng\x05apple\x03com\x00\x09marketing\xc0\x04",
                &["eng.apple.com", "marketing.apple.com"],
            ),
            // A pointer to a pointer, each further back.
            (
                b"\x01a\x00\x01b\xc0\x00\x01c\xc0\x03",
                &["a", "b.a", "c.b.a"],
            ),
        ];
        for (value, names) in cases {
            let names = names.iter().map(|name| name.to_string()).collect();
            assert_eq!(decode(value), Some(names), "{value:?}");
        }
    }

    #[test]
    fn rejects_malformed_names() {
        let mut overlong = Vec::new();
        for _ in 0..4 {
            overlong.push(63);
            overlong.extend_from_slice(&[b'a'; 63]);
        }
        overlong.push(0);
        let mut longest = overlong[..4 * 64 - 2].to_vec();
        longest[3 * 64] = 61;
        longest.push(0);
        assert_eq!(longest.len(), MAX_NAME_LEN);
        assert!(decode(&longest).is_some());

        let cases: &[(&str, &[u8])] = &[
            ("truncated label", b"\x07exam"),
            ("no terminator", b"\x03com"),
            ("truncated pointer", b"\x01a\x00\xc0"),
            ("pointer to itself", b"\xc0\x00"),
            ("forward pointer", b"\xc0\x02\x00"),
            ("pointer out of bounds", b"\x01a\x00\xff\xff"),
            ("loop", b"\x01a\xc0\x00"),
            ("pointers back and forth", b"\x01a\xc0\x04\x01b\xc0\x00"),
            ("reserved label type 01", b"\x41a\x00"),
            ("reserved label type 10", b"\x81a\x00"),
            ("invalid UTF-8", b"\x01\xff\x00"),
            ("overlong", &overlong),
        ];
        for (why, value) in cases {
            assert_eq!(decode(value), None, "{why}");
        }
    }

    #[test]
    fn encodes() {
        let names: Vec<DomainName> = ["eng.apple.com", "b"]
            .iter()
            .map(|name| name.parse().unwrap())
            .collect();
        let value = encode(&names);
        assert_eq!(value, b"\x03eng\x05apple\x03com\x00\x01b\x00");
        assert_eq!(
            decode(&value).unwrap(),
            ["eng.apple.com", "b"].map(String::from)
        );
    }
}

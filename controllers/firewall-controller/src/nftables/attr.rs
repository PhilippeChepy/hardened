//! Netlink attributes (`struct nlattr`): written into messages, and read back from the kernel's.

/// `NLA_F_NESTED`: the attribute holds attributes.
const NESTED: u16 = 0x8000;
/// The flags of an attribute's type.
const TYPE_MASK: u16 = 0x3fff;
/// `struct nlattr`'s length.
const HEADER_LEN: usize = 4;

/// Attributes being written.
#[derive(Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// No attributes yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The attributes written, each padded to 4 bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Writes `kind` holding `value`. Netlink's lengths are u16: our messages stay far below.
    pub fn bytes(&mut self, kind: u16, value: &[u8]) -> &mut Self {
        self.header(kind, value.len());
        self.bytes.extend_from_slice(value);
        self.pad();
        self
    }

    /// Writes `kind` holding `value` NUL-terminated, as nf_tables' strings are.
    pub fn string(&mut self, kind: u16, value: &str) -> &mut Self {
        let mut bytes = Vec::with_capacity(value.len() + 1);
        bytes.extend_from_slice(value.as_bytes());
        bytes.push(0);
        self.bytes(kind, &bytes)
    }

    /// Writes `kind` holding `value` in network order, as nf_tables' numbers are.
    pub fn be32(&mut self, kind: u16, value: u32) -> &mut Self {
        self.bytes(kind, &value.to_be_bytes())
    }

    /// Writes `kind` holding `value` in network order.
    pub fn be64(&mut self, kind: u16, value: u64) -> &mut Self {
        self.bytes(kind, &value.to_be_bytes())
    }

    /// Writes `kind` holding the attributes `nested` writes.
    pub fn nested(&mut self, kind: u16, nested: impl FnOnce(&mut Self)) -> &mut Self {
        let start = self.bytes.len();
        self.header(kind | NESTED, 0);
        nested(self);
        let len = self.bytes.len() - start;
        let len = u16::try_from(len).unwrap_or(u16::MAX);
        self.bytes[start..start + 2].copy_from_slice(&len.to_ne_bytes());
        self
    }

    fn header(&mut self, kind: u16, value_len: usize) {
        let len = u16::try_from(HEADER_LEN + value_len).unwrap_or(u16::MAX);
        self.bytes.extend_from_slice(&len.to_ne_bytes());
        self.bytes.extend_from_slice(&kind.to_ne_bytes());
    }

    fn pad(&mut self) {
        let padded = self.bytes.len().next_multiple_of(4);
        self.bytes.resize(padded, 0);
    }
}

/// An attribute read: its type (without the flags) and value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attr<'a> {
    /// Its type.
    pub kind: u16,
    /// Its value.
    pub value: &'a [u8],
}

impl<'a> Attr<'a> {
    /// The value as a NUL-terminated string, `None` when not one.
    #[must_use]
    pub fn string(self) -> Option<&'a str> {
        let (nul, text) = self.value.split_last()?;
        if *nul != 0 {
            return None;
        }
        std::str::from_utf8(text).ok()
    }

    /// The value as a big-endian u32.
    #[must_use]
    pub fn be32(self) -> Option<u32> {
        Some(u32::from_be_bytes(self.value.try_into().ok()?))
    }

    /// The value as a big-endian u64.
    #[must_use]
    pub fn be64(self) -> Option<u64> {
        Some(u64::from_be_bytes(self.value.try_into().ok()?))
    }

    /// The attributes nested in the value.
    #[must_use]
    pub fn nested(self) -> Attrs<'a> {
        Attrs(self.value)
    }
}

/// The attributes of a buffer, in order; a truncated one ends them.
#[derive(Debug, Clone, Copy)]
pub struct Attrs<'a>(pub &'a [u8]);

impl<'a> Iterator for Attrs<'a> {
    type Item = Attr<'a>;

    fn next(&mut self) -> Option<Attr<'a>> {
        let header = self.0.first_chunk::<HEADER_LEN>()?;
        let len = usize::from(u16::from_ne_bytes([header[0], header[1]]));
        let kind = u16::from_ne_bytes([header[2], header[3]]) & TYPE_MASK;
        let value = self.0.get(HEADER_LEN..len)?;
        self.0 = self.0.get(len.next_multiple_of(4)..).unwrap_or_default();
        Some(Attr { kind, value })
    }
}

impl<'a> Attrs<'a> {
    /// The first attribute of type `kind`.
    #[must_use]
    pub fn find(self, kind: u16) -> Option<Attr<'a>> {
        Iterator::find(&mut { self }, |attr: &Attr<'a>| attr.kind == kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_and_reads_back() {
        let mut writer = Writer::new();
        writer
            .string(1, "filter")
            .be32(2, 7)
            .nested(3, |nested| {
                nested.be64(1, 42).bytes(2, &[1]);
            })
            .bytes(4, &[]);
        let bytes = writer.into_bytes();
        assert_eq!(bytes.len() % 4, 0);
        // "filter\0" is 7 bytes: 11 with the header, padded to 12.
        assert_eq!(&bytes[..4], [11, 0, 1, 0]);
        assert_eq!(&bytes[4..12], b"filter\0\0");
        let attrs: Vec<_> = Attrs(&bytes).collect();
        assert_eq!(attrs.len(), 4);
        assert_eq!(attrs[0].string(), Some("filter"));
        assert_eq!(attrs[1].be32(), Some(7));
        assert_eq!(attrs[2].kind, 3, "without NLA_F_NESTED");
        let nested: Vec<_> = attrs[2].nested().collect();
        assert_eq!(nested[0].be64(), Some(42));
        assert_eq!(nested[1].value, [1]);
        assert_eq!(attrs[3].value, [] as [u8; 0]);
        assert_eq!(Attrs(&bytes).find(2).and_then(Attr::be32), Some(7));
    }

    #[test]
    fn reading_stops_at_a_truncated_attribute() {
        let mut writer = Writer::new();
        writer.be32(1, 1).be32(2, 2);
        let bytes = writer.into_bytes();
        assert_eq!(Attrs(&bytes[..12]).count(), 1);
        assert_eq!(Attrs(&[8, 0, 1]).count(), 0);
        // A length below the header's.
        assert_eq!(Attrs(&[2, 0, 1, 0, 0, 0, 0, 0]).count(), 0);
        let not_a_string = Attr {
            kind: 1,
            value: b"ab",
        };
        assert_eq!(not_a_string.string(), None);
    }
}

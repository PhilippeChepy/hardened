//! D-Bus messages, as far as kubelet's calls to logind need: little-endian, header fields of the
//! basic types the specification gives them, bodies of strings, booleans, integers, unix fds and
//! a variant of a `u64`.

use std::fmt;

/// The longest message accepted: kubelet's are a few hundred bytes.
const MAX_LENGTH: usize = 64 * 1024;
/// The fixed part of the header, up to the header fields' array length included.
const FIXED_HEADER: usize = 16;

/// A message's type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    MethodCall = 1,
    MethodReturn = 2,
    Error = 3,
    Signal = 4,
}

/// The sender expects no reply (`NO_REPLY_EXPECTED`).
pub const NO_REPLY_EXPECTED: u8 = 0x1;

/// A message, its body encoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub kind: Kind,
    pub flags: u8,
    pub serial: u32,
    pub path: Option<String>,
    pub interface: Option<String>,
    pub member: Option<String>,
    pub error_name: Option<String>,
    pub reply_serial: Option<u32>,
    pub destination: Option<String>,
    pub sender: Option<String>,
    pub signature: String,
    /// The number of unix fds sent with it.
    pub unix_fds: u32,
    pub body: Vec<u8>,
}

/// Why a message cannot be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid D-Bus message: {0}")]
pub struct Invalid(pub &'static str);

impl Message {
    /// A message of `kind`, with no field set and an empty body.
    #[must_use]
    pub fn new(kind: Kind, serial: u32) -> Self {
        Self {
            kind,
            flags: 0,
            serial,
            path: None,
            interface: None,
            member: None,
            error_name: None,
            reply_serial: None,
            destination: None,
            sender: None,
            signature: String::new(),
            unix_fds: 0,
            body: Vec::new(),
        }
    }

    /// The message at the start of `bytes` and its length, `None` until it is all there.
    ///
    /// # Errors
    ///
    /// When it is not a little-endian D-Bus message of version 1 within the size limit, or a
    /// header field is malformed.
    pub fn parse(bytes: &[u8]) -> Result<Option<(Self, usize)>, Invalid> {
        let Some(fixed) = bytes.get(..FIXED_HEADER) else {
            return Ok(None);
        };
        let mut reader = Reader::new(fixed, 0);
        if reader.byte()? != b'l' {
            return Err(Invalid("not little-endian"));
        }
        let kind = match reader.byte()? {
            1 => Kind::MethodCall,
            2 => Kind::MethodReturn,
            3 => Kind::Error,
            4 => Kind::Signal,
            _ => return Err(Invalid("unknown message type")),
        };
        let flags = reader.byte()?;
        if reader.byte()? != 1 {
            return Err(Invalid("not protocol version 1"));
        }
        let body_length = to_usize(reader.u32()?)?;
        let serial = reader.u32()?;
        let fields_length = to_usize(reader.u32()?)?;
        let body_start = align(
            FIXED_HEADER
                .checked_add(fields_length)
                .ok_or(Invalid("too long"))?,
            8,
        );
        let length = body_start
            .checked_add(body_length)
            .filter(|length| *length <= MAX_LENGTH)
            .ok_or(Invalid("too long"))?;
        let Some(message) = bytes.get(..length) else {
            return Ok(None);
        };
        let mut parsed = Self::new(kind, serial);
        parsed.flags = flags;
        let fields_end = FIXED_HEADER + fields_length;
        let fields = message
            .get(FIXED_HEADER..fields_end)
            .ok_or(Invalid("truncated"))?;
        let mut reader = Reader::new(fields, FIXED_HEADER);
        while reader.offset < fields_end {
            reader.align(8)?;
            let code = reader.byte()?;
            let signature = reader.signature()?;
            match (code, signature.as_str()) {
                (1, "o") => parsed.path = Some(reader.string()?),
                (2, "s") => parsed.interface = Some(reader.string()?),
                (3, "s") => parsed.member = Some(reader.string()?),
                (4, "s") => parsed.error_name = Some(reader.string()?),
                (5, "u") => parsed.reply_serial = Some(reader.u32()?),
                (6, "s") => parsed.destination = Some(reader.string()?),
                (7, "s") => parsed.sender = Some(reader.string()?),
                (8, "g") => parsed.signature = reader.signature()?,
                (9, "u") => parsed.unix_fds = reader.u32()?,
                // Unknown fields are ignored, as the specification requires.
                (_, "s" | "o") => {
                    reader.string()?;
                }
                (_, "g") => {
                    reader.signature()?;
                }
                (_, "u") => {
                    reader.u32()?;
                }
                _ => return Err(Invalid("unsupported header field type")),
            }
        }
        parsed.body = message
            .get(body_start..)
            .ok_or(Invalid("truncated"))?
            .to_vec();
        Ok(Some((parsed, length)))
    }

    /// The message, encoded.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut fields = Writer::at(FIXED_HEADER);
        let strings = [
            (1, "o", &self.path),
            (2, "s", &self.interface),
            (3, "s", &self.member),
            (4, "s", &self.error_name),
            (6, "s", &self.destination),
            (7, "s", &self.sender),
        ];
        for (code, signature, value) in strings {
            if let Some(value) = value {
                fields.field(code, signature);
                fields.string(value);
            }
        }
        if let Some(serial) = self.reply_serial {
            fields.field(5, "u");
            fields.u32(serial);
        }
        if !self.signature.is_empty() {
            fields.field(8, "g");
            fields.signature(&self.signature);
        }
        if self.unix_fds > 0 {
            fields.field(9, "u");
            fields.u32(self.unix_fds);
        }
        let fields = fields.bytes;
        let mut message = Vec::with_capacity(FIXED_HEADER + fields.len() + 8 + self.body.len());
        message.extend_from_slice(&[b'l', self.kind as u8, self.flags, 1]);
        message.extend_from_slice(&length_u32(self.body.len()).to_le_bytes());
        message.extend_from_slice(&self.serial.to_le_bytes());
        message.extend_from_slice(&length_u32(fields.len()).to_le_bytes());
        message.extend_from_slice(&fields);
        message.resize(align(message.len(), 8), 0);
        message.extend_from_slice(&self.body);
        message
    }

    /// The body's leading strings (`s`, `o`), for a call whose signature starts with them.
    ///
    /// # Errors
    ///
    /// When the signature does not start with `count` strings, or the body is malformed.
    pub fn strings(&self, count: usize) -> Result<Vec<String>, Invalid> {
        let kinds = self
            .signature
            .get(..count)
            .ok_or(Invalid("too few arguments"))?;
        if !kinds.bytes().all(|kind| matches!(kind, b's' | b'o')) {
            return Err(Invalid("arguments are not strings"));
        }
        let mut reader = Reader::new(&self.body, 0);
        (0..count).map(|_| reader.string()).collect()
    }

    /// A reply to `call`, from `sender`.
    #[must_use]
    pub fn reply_to(call: &Self, serial: u32, sender: &str) -> Self {
        let mut reply = Self::new(Kind::MethodReturn, serial);
        reply.reply_serial = Some(call.serial);
        reply.destination.clone_from(&call.sender);
        reply.sender = Some(sender.to_owned());
        reply
    }

    /// An error reply to `call`, from `sender`.
    #[must_use]
    pub fn error_to(call: &Self, serial: u32, sender: &str, name: &str, text: &str) -> Self {
        let mut reply = Self::reply_to(call, serial, sender);
        reply.kind = Kind::Error;
        reply.error_name = Some(name.to_owned());
        reply.signature = "s".to_owned();
        reply.body = Body::default().string(text).into_bytes();
        reply
    }
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let field = |value: &Option<String>| value.clone().unwrap_or_default();
        write!(
            f,
            "{:?} {}.{} on {}",
            self.kind,
            field(&self.interface),
            field(&self.member),
            field(&self.path)
        )
    }
}

/// A body being encoded, aligned from its start (itself 8-aligned in the message).
#[derive(Debug, Default)]
pub struct Body(Writer);

impl Body {
    #[must_use]
    pub fn string(mut self, value: &str) -> Self {
        self.0.string(value);
        self
    }

    #[must_use]
    pub fn u32(mut self, value: u32) -> Self {
        self.0.u32(value);
        self
    }

    #[must_use]
    pub fn boolean(self, value: bool) -> Self {
        self.u32(value.into())
    }

    /// A variant holding a `u64` (`v` of `t`).
    #[must_use]
    pub fn variant_u64(mut self, value: u64) -> Self {
        self.0.signature("t");
        self.0.pad(8);
        self.0.bytes.extend_from_slice(&value.to_le_bytes());
        self
    }

    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0.bytes
    }
}

#[derive(Debug, Default)]
struct Writer {
    bytes: Vec<u8>,
    /// Where `bytes` starts in the message, for alignment.
    base: usize,
}

impl Writer {
    fn at(base: usize) -> Self {
        Self {
            bytes: Vec::new(),
            base,
        }
    }

    fn pad(&mut self, alignment: usize) {
        let end = self.base + self.bytes.len();
        self.bytes.resize(align(end, alignment) - self.base, 0);
    }

    fn field(&mut self, code: u8, signature: &str) {
        self.pad(8);
        self.bytes.push(code);
        self.signature(signature);
    }

    fn u32(&mut self, value: u32) {
        self.pad(4);
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    fn string(&mut self, value: &str) {
        self.u32(length_u32(value.len()));
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
    }

    fn signature(&mut self, value: &str) {
        // Signatures are at most 255 bytes; ours are a few.
        self.bytes
            .push(u8::try_from(value.len()).unwrap_or(u8::MAX));
        self.bytes.extend_from_slice(value.as_bytes());
        self.bytes.push(0);
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    /// Where `bytes` starts in the message.
    base: usize,
    /// The position in the message.
    offset: usize,
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8], base: usize) -> Self {
        Self {
            bytes,
            base,
            offset: base,
        }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], Invalid> {
        let start = self.offset - self.base;
        let taken = start
            .checked_add(count)
            .and_then(|end| self.bytes.get(start..end))
            .ok_or(Invalid("truncated"))?;
        self.offset += count;
        Ok(taken)
    }

    fn align(&mut self, alignment: usize) -> Result<(), Invalid> {
        let padding = align(self.offset, alignment) - self.offset;
        if self.take(padding)?.iter().any(|byte| *byte != 0) {
            return Err(Invalid("non-zero padding"));
        }
        Ok(())
    }

    fn byte(&mut self) -> Result<u8, Invalid> {
        self.take(1)?.first().copied().ok_or(Invalid("truncated"))
    }

    fn u32(&mut self) -> Result<u32, Invalid> {
        self.align(4)?;
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| Invalid("truncated"))?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn string(&mut self) -> Result<String, Invalid> {
        let length = to_usize(self.u32()?)?;
        self.text(length)
    }

    fn signature(&mut self) -> Result<String, Invalid> {
        let length = usize::from(self.byte()?);
        self.text(length)
    }

    /// `length` bytes of UTF-8, then a NUL.
    fn text(&mut self, length: usize) -> Result<String, Invalid> {
        let text = self.take(length)?;
        if self.byte()? != 0 || text.contains(&0) {
            return Err(Invalid("string without its NUL"));
        }
        String::from_utf8(text.to_vec()).map_err(|_| Invalid("string not UTF-8"))
    }
}

#[must_use]
fn align(offset: usize, alignment: usize) -> usize {
    offset.div_ceil(alignment) * alignment
}

fn to_usize(length: u32) -> Result<usize, Invalid> {
    usize::try_from(length).map_err(|_| Invalid("too long"))
}

/// Lengths of what this module encodes: below [`MAX_LENGTH`].
#[must_use]
fn length_u32(length: usize) -> u32 {
    u32::try_from(length).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// godbus's `Hello`, as kubelet sends it.
    fn hello() -> Message {
        let mut call = Message::new(Kind::MethodCall, 1);
        call.path = Some("/org/freedesktop/DBus".into());
        call.interface = Some("org.freedesktop.DBus".into());
        call.member = Some("Hello".into());
        call.destination = Some("org.freedesktop.DBus".into());
        call
    }

    #[test]
    fn round_trips() {
        let mut call = hello();
        call.signature = "ss".into();
        call.body = Body::default()
            .string("org.freedesktop.login1.Manager")
            .string("InhibitDelayMaxUSec")
            .into_bytes();
        let bytes = call.encode();
        let (parsed, length) = Message::parse(&bytes).unwrap().unwrap();
        assert_eq!(length, bytes.len());
        assert_eq!(parsed, call);
        assert_eq!(
            parsed.strings(2).unwrap(),
            ["org.freedesktop.login1.Manager", "InhibitDelayMaxUSec"]
        );
        assert!(parsed.strings(3).is_err());
        assert_eq!(Message::parse(&bytes[..bytes.len() - 1]).unwrap(), None);
        assert_eq!(Message::parse(&bytes[..10]).unwrap(), None);
    }

    #[test]
    fn hello_as_the_specification_encodes_it() {
        // Worked out from the specification: fields 8-aligned, their array's length without
        // the padding before the body.
        let expected: &[u8] = b"l\x01\x00\x01\x00\x00\x00\x00\x01\x00\x00\x00\x6d\x00\x00\x00\
            \x01\x01o\x00\x15\x00\x00\x00/org/freedesktop/DBus\x00\x00\x00\
            \x02\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00\
            \x03\x01s\x00\x05\x00\x00\x00Hello\x00\x00\x00\
            \x06\x01s\x00\x14\x00\x00\x00org.freedesktop.DBus\x00\x00\x00\x00";
        assert_eq!(hello().encode(), expected);
        let (parsed, _) = Message::parse(expected).unwrap().unwrap();
        assert_eq!(parsed, hello());
    }

    #[test]
    fn variants_and_errors() {
        let body = Body::default().variant_u64(30_000_000).into_bytes();
        assert_eq!(
            body,
            b"\x01t\x00\x00\x00\x00\x00\x00\x80\xc3\xc9\x01\x00\x00\x00\x00"
        );
        let error = Message::error_to(&hello(), 7, "org.freedesktop.login1", "x.Error", "no");
        let (parsed, _) = Message::parse(&error.encode()).unwrap().unwrap();
        assert_eq!(parsed.kind, Kind::Error);
        assert_eq!(parsed.reply_serial, Some(1));
        assert_eq!(parsed.strings(1).unwrap(), ["no"]);
    }

    #[test]
    fn rejects_malformed_messages() {
        let mut bytes = hello().encode();
        bytes[0] = b'B';
        assert!(Message::parse(&bytes).is_err(), "big-endian");
        let mut bytes = hello().encode();
        bytes[3] = 2;
        assert!(Message::parse(&bytes).is_err(), "version");
        let mut bytes = hello().encode();
        bytes[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(Message::parse(&bytes).is_err(), "too long");
    }
}

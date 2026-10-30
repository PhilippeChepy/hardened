//! The mounts of `/proc/self/mountinfo`.

use std::ffi::OsString;
use std::path::PathBuf;

/// The mount table of this process.
pub const MOUNTINFO: &str = "/proc/self/mountinfo";

/// A mount, as far as storage-controller cares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    /// The device number, `major:minor`.
    pub device: String,
    /// Where it is mounted.
    pub target: PathBuf,
    /// The filesystem type.
    pub fs_type: String,
    /// What it is mounted from (`/dev/vda4`, `tmpfs`).
    pub source: OsString,
}

impl Mount {
    /// The mounts of `mountinfo`, in mount order; malformed lines are skipped.
    #[must_use]
    pub fn parse_all(mountinfo: &str) -> Vec<Self> {
        mountinfo.lines().filter_map(Self::parse).collect()
    }

    /// One line: `id parent major:minor root target options [optional...] - type source ...`.
    fn parse(line: &str) -> Option<Self> {
        let mut fields = line.split(' ');
        let device = fields.nth(2)?.to_owned();
        let target = PathBuf::from(unescape(fields.nth(1)?));
        let mut after_separator = fields.skip_while(|field| *field != "-").skip(1);
        let fs_type = after_separator.next()?.to_owned();
        let source = unescape(after_separator.next()?);
        Some(Self {
            device,
            target,
            fs_type,
            source,
        })
    }
}

/// Decodes the octal escapes of mountinfo (`\040` for a space).
#[must_use]
fn unescape(field: &str) -> OsString {
    use std::os::unix::ffi::OsStringExt as _;

    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        let octal = bytes
            .get(i + 1..i + 4)
            .filter(|digits| digits.iter().all(|d| (b'0'..=b'7').contains(d)));
        match (bytes[i], octal) {
            (b'\\', Some(digits)) => {
                out.push(
                    digits
                        .iter()
                        .fold(0u8, |n, d| n.wrapping_mul(8) + (d - b'0')),
                );
                i += 4;
            }
            (byte, _) => {
                out.push(byte);
                i += 1;
            }
        }
    }
    OsString::from_vec(out)
}

#[cfg(test)]
mod tests {
    use std::os::unix::ffi::OsStringExt as _;

    use super::*;

    #[test]
    fn parses_mounts() {
        let mountinfo = "\
22 1 254:0 / / ro,relatime shared:1 - erofs /dev/dm-0 ro
40 22 253:1 / /var\\040x rw - ext4 /dev/mapper/state rw
garbage
";
        assert_eq!(
            Mount::parse_all(mountinfo),
            [
                Mount {
                    device: "254:0".into(),
                    target: "/".into(),
                    fs_type: "erofs".into(),
                    source: "/dev/dm-0".into(),
                },
                Mount {
                    device: "253:1".into(),
                    target: "/var x".into(),
                    fs_type: "ext4".into(),
                    source: "/dev/mapper/state".into(),
                },
            ]
        );
    }

    #[test]
    fn unescapes_octal() {
        assert_eq!(unescape("a\\040b\\011c"), "a b\tc");
        assert_eq!(unescape("trailing\\04"), "trailing\\04");
        assert_eq!(
            unescape("\\377"),
            OsString::from_vec(vec![0xff]),
            "not UTF-8"
        );
    }
}

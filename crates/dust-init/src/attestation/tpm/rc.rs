//! TPM_RC response codes (TPM 2.0 Part 2, §6.6), decoded for humans.

use std::fmt;

/// A non-success TPM_RC returned by the TPM (or by the kernel resource manager).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseCode(pub u32);

/// Format-one codes carry a handle, session or parameter number.
const RC_FMT1: u16 = 0x080;
/// Format-one: the number designates a parameter rather than a handle or session.
const RC_P: u16 = 0x040;
/// Format-one with handles: numbers 8..=15 designate sessions 0..=7.
const RC_S: u16 = 0x800;
/// Format-zero: TPM 2.0 code (clear for TPM 1.2 codes).
const RC_VER1: u16 = 0x100;
/// Format-zero: vendor-defined code.
const RC_VENDOR: u16 = 0x400;

impl ResponseCode {
    /// Transient conditions where re-sending the very same command is the documented remedy.
    pub fn is_retryable(self) -> bool {
        const YIELDED: u32 = 0x908;
        const TESTING: u32 = 0x90A;
        const RETRY: u32 = 0x922;
        matches!(self.0, YIELDED | TESTING | RETRY)
    }

    /// The error of a format-one code from the TPM (`TPM_RC_POLICY_FAIL`...), without the
    /// handle, session or parameter it names.
    pub fn format_one(self) -> Option<u16> {
        let code = self.code();
        (self.layer() == 0 && code & RC_FMT1 != 0).then_some(RC_FMT1 | (code & 0x3F))
    }

    /// Software layer that produced the code (0 for the TPM itself).
    fn layer(self) -> u32 {
        self.0 >> 16
    }

    fn code(self) -> u16 {
        // Truncation intended: the upper half is the layer.
        self.0 as u16
    }
}

impl fmt::Display for ResponseCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        if self.layer() != 0 {
            return write!(f, "response code {:#x} from software layer {:#x}", self.0, self.layer());
        }
        if code & RC_FMT1 != 0 {
            let name = format_one_name(RC_FMT1 | (code & 0x3F)).unwrap_or("unknown format-one error");
            let n = (code >> 8) & 0xF;
            if code & RC_P != 0 {
                write!(f, "{name} (parameter {n}, {code:#x})")
            } else if code & RC_S != 0 {
                write!(f, "{name} (session {}, {code:#x})", n - 8)
            } else if n != 0 {
                write!(f, "{name} (handle {n}, {code:#x})")
            } else {
                write!(f, "{name} ({code:#x})")
            }
        } else if code & RC_VER1 == 0 {
            write!(f, "TPM 1.2 response code {code:#x}")
        } else if code & RC_VENDOR != 0 {
            write!(f, "vendor-defined response code {code:#x}")
        } else {
            let name = format_zero_name(code).unwrap_or("unknown response code");
            write!(f, "{name} ({code:#x})")
        }
    }
}

fn format_one_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0x081 => "TPM_RC_ASYMMETRIC",
        0x082 => "TPM_RC_ATTRIBUTES",
        0x083 => "TPM_RC_HASH",
        0x084 => "TPM_RC_VALUE",
        0x085 => "TPM_RC_HIERARCHY",
        0x087 => "TPM_RC_KEY_SIZE",
        0x088 => "TPM_RC_MGF",
        0x089 => "TPM_RC_MODE",
        0x08A => "TPM_RC_TYPE",
        0x08B => "TPM_RC_HANDLE",
        0x08C => "TPM_RC_KDF",
        0x08D => "TPM_RC_RANGE",
        0x08E => "TPM_RC_AUTH_FAIL",
        0x08F => "TPM_RC_NONCE",
        0x090 => "TPM_RC_PP",
        0x092 => "TPM_RC_SCHEME",
        0x095 => "TPM_RC_SIZE",
        0x096 => "TPM_RC_SYMMETRIC",
        0x097 => "TPM_RC_TAG",
        0x098 => "TPM_RC_SELECTOR",
        0x09A => "TPM_RC_INSUFFICIENT",
        0x09B => "TPM_RC_SIGNATURE",
        0x09C => "TPM_RC_KEY",
        0x09D => "TPM_RC_POLICY_FAIL",
        0x09F => "TPM_RC_INTEGRITY",
        0x0A0 => "TPM_RC_TICKET",
        0x0A1 => "TPM_RC_RESERVED_BITS",
        0x0A2 => "TPM_RC_BAD_AUTH",
        0x0A3 => "TPM_RC_EXPIRED",
        0x0A4 => "TPM_RC_POLICY_CC",
        0x0A5 => "TPM_RC_BINDING",
        0x0A6 => "TPM_RC_CURVE",
        0x0A7 => "TPM_RC_ECC_POINT",
        _ => return None,
    })
}

fn format_zero_name(code: u16) -> Option<&'static str> {
    Some(match code {
        0x100 => "TPM_RC_INITIALIZE",
        0x101 => "TPM_RC_FAILURE",
        0x103 => "TPM_RC_SEQUENCE",
        0x10B => "TPM_RC_PRIVATE",
        0x119 => "TPM_RC_HMAC",
        0x120 => "TPM_RC_DISABLED",
        0x121 => "TPM_RC_EXCLUSIVE",
        0x124 => "TPM_RC_AUTH_TYPE",
        0x125 => "TPM_RC_AUTH_MISSING",
        0x126 => "TPM_RC_POLICY",
        0x127 => "TPM_RC_PCR",
        0x128 => "TPM_RC_PCR_CHANGED",
        0x12D => "TPM_RC_UPGRADE",
        0x12E => "TPM_RC_TOO_MANY_CONTEXTS",
        0x12F => "TPM_RC_AUTH_UNAVAILABLE",
        0x130 => "TPM_RC_REBOOT",
        0x131 => "TPM_RC_UNBALANCED",
        0x142 => "TPM_RC_COMMAND_SIZE",
        0x143 => "TPM_RC_COMMAND_CODE",
        0x144 => "TPM_RC_AUTHSIZE",
        0x145 => "TPM_RC_AUTH_CONTEXT",
        0x146 => "TPM_RC_NV_RANGE",
        0x147 => "TPM_RC_NV_SIZE",
        0x148 => "TPM_RC_NV_LOCKED",
        0x149 => "TPM_RC_NV_AUTHORIZATION",
        0x14A => "TPM_RC_NV_UNINITIALIZED",
        0x14B => "TPM_RC_NV_SPACE",
        0x14C => "TPM_RC_NV_DEFINED",
        0x150 => "TPM_RC_BAD_CONTEXT",
        0x151 => "TPM_RC_CPHASH",
        0x152 => "TPM_RC_PARENT",
        0x153 => "TPM_RC_NEEDS_TEST",
        0x154 => "TPM_RC_NO_RESULT",
        0x155 => "TPM_RC_SENSITIVE",
        0x901 => "TPM_RC_CONTEXT_GAP",
        0x902 => "TPM_RC_OBJECT_MEMORY",
        0x903 => "TPM_RC_SESSION_MEMORY",
        0x904 => "TPM_RC_MEMORY",
        0x905 => "TPM_RC_SESSION_HANDLES",
        0x906 => "TPM_RC_OBJECT_HANDLES",
        0x907 => "TPM_RC_LOCALITY",
        0x908 => "TPM_RC_YIELDED",
        0x909 => "TPM_RC_CANCELED",
        0x90A => "TPM_RC_TESTING",
        0x920 => "TPM_RC_NV_RATE",
        0x921 => "TPM_RC_LOCKOUT",
        0x922 => "TPM_RC_RETRY",
        0x923 => "TPM_RC_NV_UNAVAILABLE",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_format_one_locations() {
        assert_eq!(ResponseCode(0x18B).to_string(), "TPM_RC_HANDLE (handle 1, 0x18b)");
        assert_eq!(ResponseCode(0x1C4).to_string(), "TPM_RC_VALUE (parameter 1, 0x1c4)");
        assert_eq!(ResponseCode(0x9A2).to_string(), "TPM_RC_BAD_AUTH (session 1, 0x9a2)");
        assert_eq!(ResponseCode(0x2C3).to_string(), "TPM_RC_HASH (parameter 2, 0x2c3)");
        assert_eq!(ResponseCode(0x0A6).to_string(), "TPM_RC_CURVE (0xa6)");
        assert_eq!(ResponseCode(0x99D).format_one(), Some(0x09D));
        assert_eq!(ResponseCode(0x1DF).format_one(), Some(0x09F));
        assert_eq!(ResponseCode(0x921).format_one(), None);
        assert_eq!(ResponseCode(0x8_099D).format_one(), None);
    }

    #[test]
    fn decodes_format_zero_and_warnings() {
        assert_eq!(ResponseCode(0x101).to_string(), "TPM_RC_FAILURE (0x101)");
        assert_eq!(ResponseCode(0x921).to_string(), "TPM_RC_LOCKOUT (0x921)");
        assert_eq!(ResponseCode(0x01E).to_string(), "TPM 1.2 response code 0x1e");
        assert_eq!(ResponseCode(0x500).to_string(), "vendor-defined response code 0x500");
        assert!(ResponseCode(0x922).is_retryable());
        assert!(!ResponseCode(0x921).is_retryable());
        assert!(ResponseCode(0x8_0001).to_string().contains("software layer 0x8"));
    }
}

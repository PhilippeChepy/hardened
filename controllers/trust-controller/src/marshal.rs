//! TPM 2.0 wire format (TPM 2.0 Part 1, §18): big-endian integers, size-prefixed TPM2B
//! buffers, and the command/response framing shared by every command.

use crate::response_code::ResponseCode;
use crate::tpm_error::TpmError;

const ST_NO_SESSIONS: u16 = 0x8001;
const ST_SESSIONS: u16 = 0x8002;
/// The password authorization pseudo-session.
const RS_PW: u32 = 0x4000_0009;
/// tag, commandSize/responseSize, commandCode/responseCode.
pub const HEADER_LEN: usize = 10;

/// Builds marshalled structures. Methods chain.
#[derive(Debug, Default)]
pub struct Writer(Vec<u8>);

impl Writer {
    /// Appends a byte.
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }

    /// Appends a big-endian u16.
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    /// Appends a big-endian u32.
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_be_bytes())
    }

    /// Appends `v` as is.
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.0.extend_from_slice(v);
        self
    }

    /// A TPM2B: `v` behind a u16 size.
    pub fn tpm2b(&mut self, v: &[u8]) -> &mut Self {
        self.sized(|w| {
            w.bytes(v);
        })
    }

    /// Whatever `f` writes, behind a u16 size (a TPM2B of a structure).
    pub fn sized(&mut self, f: impl FnOnce(&mut Self)) -> &mut Self {
        let at = self.0.len();
        self.u16(0);
        f(self);
        let len = u16::try_from(self.0.len() - at - 2).expect("TPM2B exceeds 64 KiB");
        self.0[at..at + 2].copy_from_slice(&len.to_be_bytes());
        self
    }

    /// The marshalled bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// Authorization of a command's handles.
#[derive(Debug, Clone, Copy)]
pub enum Auth<'bytes> {
    /// No authorization area (TPM_ST_NO_SESSIONS).
    None,
    /// One TPM_RS_PW session with an empty password: the hierarchies and keys used have none.
    EmptyPassword,
    /// One policy session, flushed once the command succeeds. Without PolicyAuthValue or
    /// PolicyPassword in its policy, it carries no HMAC.
    Policy { session: u32, nonce: &'bytes [u8] },
    /// An empty password for the first handle, then a policy session for the second (as
    /// [`Auth::Policy`]).
    PasswordThenPolicy { session: u32, nonce: &'bytes [u8] },
}

/// Marshals a command: header, handle area, authorization area, then what `params` writes.
#[must_use]
pub fn command(
    code: u32,
    handles: &[u32],
    auth: Auth<'_>,
    params: impl FnOnce(&mut Writer),
) -> Vec<u8> {
    // TPMS_AUTH_COMMAND: sessionHandle, nonceCaller, sessionAttributes (continueSession clear),
    // hmac (the password for TPM_RS_PW, nothing for a policy session): both empty.
    let sessions: &[(u32, &[u8])] = match auth {
        Auth::None => &[],
        Auth::EmptyPassword => &[(RS_PW, &[])],
        Auth::Policy { session, nonce } => &[(session, nonce)],
        Auth::PasswordThenPolicy { session, nonce } => &[(RS_PW, &[]), (session, nonce)],
    };
    let mut w = Writer::default();
    w.u16(if sessions.is_empty() {
        ST_NO_SESSIONS
    } else {
        ST_SESSIONS
    })
    .u32(0)
    .u32(code);
    for &handle in handles {
        w.u32(handle);
    }
    if !sessions.is_empty() {
        let mut area = Writer::default();
        for &(handle, nonce) in sessions {
            area.u32(handle).tpm2b(nonce).u8(0).tpm2b(&[]);
        }
        let area = area.into_bytes();
        // authorizationSize, then the sessions.
        w.u32(len_u32(&area)).bytes(&area);
    }
    params(&mut w);
    let mut bytes = w.into_bytes();
    let size = len_u32(&bytes);
    bytes[2..6].copy_from_slice(&size.to_be_bytes());
    bytes
}

fn len_u32(bytes: &[u8]) -> u32 {
    u32::try_from(bytes.len()).expect("TPM command exceeds 4 GiB")
}

/// The response code of a raw response, if it is long enough to carry one.
#[must_use]
pub fn response_code(response: &[u8]) -> Option<u32> {
    let rc = response.get(6..HEADER_LEN)?;
    Some(u32::from_be_bytes(rc.try_into().ok()?))
}

/// The areas of a successful response.
#[derive(Debug)]
pub struct Response<'response> {
    /// The handle area.
    pub handles: Reader<'response>,
    /// The parameter area.
    pub params: Reader<'response>,
}

/// Checks a response's framing and code, and splits it into its `handles` handle(s) and
/// parameter area (the trailing authorization area, if any, is not checked).
pub fn response(bytes: &[u8], handles: usize) -> Result<Response<'_>, TpmError> {
    let mut r = Reader::new(bytes);
    let tag = r.u16()?;
    let size = r.u32()?;
    let rc = r.u32()?;
    if usize::try_from(size).ok() != Some(bytes.len()) {
        return Err(TpmError::Malformed(
            "response size does not match its header",
        ));
    }
    if rc != 0 {
        return Err(TpmError::Response(ResponseCode(rc)));
    }
    let handles = Reader::new(r.take(4 * handles)?);
    let params = match tag {
        ST_NO_SESSIONS => r,
        ST_SESSIONS => {
            let len = r.u32()?;
            Reader::new(r.take(usize::try_from(len).map_err(|_| TRUNCATED)?)?)
        }
        _ => return Err(TpmError::Malformed("unknown response tag")),
    };
    Ok(Response { handles, params })
}

/// Frames a successful response, with an empty password-session response if `sessions`.
#[cfg(test)]
#[must_use]
pub fn test_response(handles: &[u32], params: &[u8], sessions: bool) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(if sessions {
        ST_SESSIONS
    } else {
        ST_NO_SESSIONS
    })
    .u32(0)
    .u32(0);
    for &handle in handles {
        w.u32(handle);
    }
    if sessions {
        w.u32(len_u32(params)).bytes(params);
        w.tpm2b(&[]).u8(1).tpm2b(&[]);
    } else {
        w.bytes(params);
    }
    let mut bytes = w.into_bytes();
    let size = len_u32(&bytes);
    bytes[2..6].copy_from_slice(&size.to_be_bytes());
    bytes
}

const TRUNCATED: TpmError = TpmError::Malformed("truncated");

/// Bounds-checked cursor over a marshalled structure.
#[derive(Debug, Clone)]
pub struct Reader<'bytes>(&'bytes [u8]);

impl<'bytes> Reader<'bytes> {
    /// A reader at the start of `bytes`.
    #[must_use]
    pub fn new(bytes: &'bytes [u8]) -> Self {
        Self(bytes)
    }

    /// The next `n` bytes.
    pub fn take(&mut self, n: usize) -> Result<&'bytes [u8], TpmError> {
        let (head, tail) = self.0.split_at_checked(n).ok_or(TRUNCATED)?;
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], TpmError> {
        let (head, tail) = self.0.split_first_chunk::<N>().ok_or(TRUNCATED)?;
        self.0 = tail;
        Ok(*head)
    }

    /// The next byte.
    pub fn u8(&mut self) -> Result<u8, TpmError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    /// The next big-endian u16.
    pub fn u16(&mut self) -> Result<u16, TpmError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    /// The next big-endian u32.
    pub fn u32(&mut self) -> Result<u32, TpmError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// The contents of a TPM2B.
    pub fn tpm2b(&mut self) -> Result<&'bytes [u8], TpmError> {
        let len = self.u16()?;
        self.take(len.into())
    }

    /// The contents of a u8-sized array (the `pcrSelect` of a TPMS_PCR_SELECTION).
    pub fn u8_sized(&mut self) -> Result<&'bytes [u8], TpmError> {
        let len = self.u8()?;
        self.take(len.into())
    }

    /// Everything not read yet.
    #[must_use]
    pub fn rest(self) -> &'bytes [u8] {
        self.0
    }

    /// Fails unless the structure was fully consumed.
    pub fn finish(self) -> Result<(), TpmError> {
        match self.0 {
            [] => Ok(()),
            _ => Err(TpmError::Malformed("trailing bytes")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writer_is_big_endian_and_sizes_tpm2b() {
        let mut w = Writer::default();
        w.u8(1)
            .u16(0x0203)
            .u32(0x0405_0607)
            .tpm2b(b"ab")
            .sized(|w| {
                w.u16(0xbeef).tpm2b(&[]);
            });
        assert_eq!(
            w.into_bytes(),
            [
                1, 2, 3, 4, 5, 6, 7, 0, 2, b'a', b'b', 0, 4, 0xbe, 0xef, 0, 0
            ]
        );
    }

    #[test]
    fn reader_is_bounds_checked() {
        let mut r = Reader::new(&[0, 3, 1, 2]);
        assert!(matches!(r.tpm2b(), Err(TpmError::Malformed("truncated"))));
        let mut r = Reader::new(&[0, 1, 9, 0xaa]);
        assert_eq!(r.tpm2b().unwrap(), [9]);
        assert!(r.clone().finish().is_err());
        assert_eq!(r.u8().unwrap(), 0xaa);
        r.finish().unwrap();
    }

    #[test]
    fn response_errors_are_decoded() {
        let rsp = [0x80, 0x01, 0, 0, 0, 0x0a, 0, 0, 0x01, 0x8b];
        let err = response(&rsp, 0).unwrap_err();
        assert!(matches!(err, TpmError::Response(ResponseCode(0x18b))));
        assert_eq!(response_code(&rsp), Some(0x18b));
    }

    #[test]
    fn response_framing_is_validated() {
        // Size field says 11, buffer is 10 bytes.
        let rsp = [0x80, 0x01, 0, 0, 0, 0x0b, 0, 0, 0, 0];
        assert!(matches!(response(&rsp, 0), Err(TpmError::Malformed(_))));
        assert!(matches!(
            response(&rsp[..4], 0),
            Err(TpmError::Malformed("truncated"))
        ));
    }

    #[test]
    fn session_response_splits_parameters_from_auth_area() {
        #[rustfmt::skip]
        let rsp = [
            0x80, 0x02, 0, 0, 0, 0x1a, 0, 0, 0, 0, // header (26 bytes)
            0x80, 0, 0, 0x02,                      // handle
            0, 0, 0, 0x03, 0, 1, 0x42,             // parameterSize, parameters
            0, 0, 0x01, 0, 0,                      // TPMS_AUTH_RESPONSE
        ];
        let Response {
            mut handles,
            mut params,
        } = response(&rsp, 1).unwrap();
        assert_eq!(handles.u32().unwrap(), 0x8000_0002);
        assert_eq!(params.tpm2b().unwrap(), [0x42]);
        params.finish().unwrap();
    }
}

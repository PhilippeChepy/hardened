//! Structured command-line values, parsed once at the CLI boundary.

use std::fmt;
use std::str::FromStr;

use tonic::transport::Uri;
use workload_controller::workloads::Mount;

/// Port `machine-apiproxy` listens on by default.
pub const DEFAULT_PORT: u16 = 7443;

/// A `KEY=VALUE` environment variable with a non-empty key; the value may be empty or contain
/// `=`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvVar {
    /// The variable's name, never empty.
    pub key: String,
    pub value: String,
}

impl FromStr for EnvVar {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('=') {
            Some((key, value)) if !key.is_empty() => Ok(Self {
                key: key.to_owned(),
                value: value.to_owned(),
            }),
            _ => Err(format!("expected KEY=VALUE, got {s:?}")),
        }
    }
}

/// Parses `SOURCE:DESTINATION[:ro|:rw]`.
pub fn mount(s: &str) -> Result<Mount, String> {
    let mut parts = s.split(':');
    let (Some(source), Some(destination)) = (parts.next(), parts.next()) else {
        return Err(format!("expected SOURCE:DESTINATION[:ro], got {s:?}"));
    };
    if source.is_empty() || destination.is_empty() {
        return Err(format!("empty path in mount {s:?}"));
    }
    let read_only = match (parts.next(), parts.next()) {
        (None, None) | (Some("rw"), None) => false,
        (Some("ro"), None) => true,
        _ => return Err(format!("expected SOURCE:DESTINATION[:ro], got {s:?}")),
    };
    Ok(Mount {
        source: source.to_owned(),
        destination: destination.to_owned(),
        read_only,
    })
}

/// A TPM quote freshness nonce: 1 to 64 bytes, given in hex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce(Vec<u8>);

impl Nonce {
    /// The nonce's bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl FromStr for Nonce {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {e}"))?;
        match bytes.len() {
            1..=64 => Ok(Self(bytes)),
            n => Err(format!("nonce must be 1 to 64 bytes, got {n}")),
        }
    }
}

/// A `machine-apiproxy` address: an `https` URI with a host, an explicit port and no path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint(Uri);

impl Endpoint {
    /// The completed URI: `https://host:port/`.
    #[must_use]
    pub fn uri(&self) -> &Uri {
        &self.0
    }
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for Endpoint {
    type Err = String;

    /// Completes `host`, `host:port` or `https://host[:port]`, defaulting to [`DEFAULT_PORT`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let with_scheme = if s.contains("://") {
            s.to_owned()
        } else {
            format!("https://{s}")
        };
        let uri: Uri = with_scheme
            .parse()
            .map_err(|e| format!("invalid endpoint {s:?}: {e}"))?;
        if uri.scheme_str() != Some("https") {
            return Err(format!("endpoint {s:?} must use https"));
        }
        let authority = uri
            .authority()
            .ok_or_else(|| format!("endpoint {s:?} has no host"))?;
        if !matches!(uri.path(), "" | "/") {
            return Err(format!("endpoint {s:?} must not have a path"));
        }
        let port = authority.port_u16().unwrap_or(DEFAULT_PORT);
        format!("https://{}:{port}", authority.host())
            .parse()
            .map(Self)
            .map_err(|e| format!("invalid endpoint {s:?}: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_env_vars() {
        let env = |s: &str| s.parse::<EnvVar>().map(|var| (var.key, var.value));
        assert_eq!(env("A=b"), Ok(("A".into(), "b".into())));
        assert_eq!(env("A="), Ok(("A".into(), String::new())));
        assert_eq!(env("URL=a=b"), Ok(("URL".into(), "a=b".into())));
        assert!(env("A").is_err());
        assert!(env("=b").is_err());
    }

    #[test]
    fn parses_mounts() {
        let mount =
            |s| super::mount(s).map(|mount| (mount.source, mount.destination, mount.read_only));
        assert_eq!(
            mount("/var/a:/a"),
            Ok(("/var/a".into(), "/a".into(), false))
        );
        assert_eq!(
            mount("/var/a:/a:ro"),
            Ok(("/var/a".into(), "/a".into(), true))
        );
        assert_eq!(
            mount("/var/a:/a:rw"),
            Ok(("/var/a".into(), "/a".into(), false))
        );
        for bad in ["/var/a", ":/a", "/var/a:", "/var/a:/a:rx", "/var/a:/a:ro:x"] {
            assert!(mount(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_nonces() {
        assert_eq!(
            "00ff"
                .parse::<Nonce>()
                .map(|nonce| nonce.as_bytes().to_vec()),
            Ok(vec![0, 0xff])
        );
        assert!("".parse::<Nonce>().is_err());
        assert!("0g".parse::<Nonce>().is_err());
        assert!("00".repeat(65).parse::<Nonce>().is_err());
    }

    #[test]
    fn completes_endpoints() {
        let endpoint = |s: &str| s.parse::<Endpoint>().map(|endpoint| endpoint.to_string());
        assert_eq!(endpoint("10.0.0.5"), Ok("https://10.0.0.5:7443/".into()));
        assert_eq!(endpoint("node:8443"), Ok("https://node:8443/".into()));
        assert_eq!(endpoint("https://node"), Ok("https://node:7443/".into()));
        assert_eq!(endpoint("https://[::1]:9/"), Ok("https://[::1]:9/".into()));
        assert!(endpoint("http://node").is_err());
        assert!(endpoint("https://node/api").is_err());
    }
}

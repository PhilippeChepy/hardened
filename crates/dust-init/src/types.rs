//! Validated domain values.
//!
//! Each type can only hold a valid value: it is checked once, when parsed (from user-data, the
//! API, metadata or DHCP), so code receiving one never re-validates it. They deserialize from and
//! serialize to their string form.

use std::fmt;
use std::path::Path;
use std::str::FromStr;

use base64::Engine;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Why a value was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind} {value:?}: {reason}")]
pub struct InvalidValue {
    kind: &'static str,
    value: String,
    reason: &'static str,
}

impl InvalidValue {
    pub(crate) fn new(kind: &'static str, value: &str, reason: &'static str) -> Self {
        // Never echo secrets or huge inputs back.
        let value = if value.len() > 128 {
            format!("{}…", &value[..value.floor_char_boundary(128)])
        } else {
            value.to_owned()
        };
        Self { kind, value, reason }
    }

    pub fn nul_byte(value: &str) -> Self {
        Self::new("argument", value, "must not contain NUL bytes")
    }
}

/// Defines a string newtype whose constructor runs `$check: fn(&str) -> Result<(), &'static str>`.
macro_rules! validated_string {
    ($(#[$meta:meta])* $name:ident, $kind:literal, $check:expr) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, ::serde::Serialize, ::serde::Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = $crate::types::InvalidValue;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                let check: fn(&str) -> Result<(), &'static str> = $check;
                match check(&value) {
                    Ok(()) => Ok(Self(value)),
                    Err(reason) => Err($crate::types::InvalidValue::new($kind, &value, reason)),
                }
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::types::InvalidValue;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::try_from(value.to_owned())
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        // Sound: equality, ordering and hashing are those of the inner string.
        impl ::std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}
pub(crate) use validated_string;

/// RFC 1123 domain name: dot-separated labels of 1-63 alphanumerics or '-', at most 253 chars.
fn check_domain_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 253 {
        return Err("must be 1 to 253 characters");
    }
    let valid_label = |label: &str| {
        (1..=63).contains(&label.len())
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if name.split('.').all(valid_label) {
        Ok(())
    } else {
        Err("labels must be 1-63 alphanumerics or '-', not starting or ending with '-'")
    }
}

validated_string!(
    /// RFC 1123 hostname.
    Hostname,
    "hostname",
    check_domain_name
);

validated_string!(
    /// DNS search domain, with the hostname syntax (so it cannot inject into `resolv.conf`).
    DomainName,
    "domain name",
    check_domain_name
);

impl Hostname {
    /// Cleans up a hostname offered by a platform or DHCP server: first word, trailing dots
    /// stripped, lowercased; falls back to its first label when the whole name is invalid.
    pub fn sanitize(raw: &str) -> Option<Self> {
        let name = raw
            .split_whitespace()
            .next()?
            .trim_end_matches('.')
            .to_ascii_lowercase();
        let first_label = name.split('.').next().unwrap_or_default().to_owned();
        name.parse().ok().or_else(|| first_label.parse().ok())
    }

    /// Placeholder used until the real hostname is known.
    pub fn localhost() -> Self {
        Self("localhost".to_owned())
    }

    /// `hardened-<up to 8 lowercase alphanumerics of the instance ID>`, or `hardened`.
    pub fn from_instance_id(instance_id: Option<&str>) -> Self {
        let short: String = instance_id
            .unwrap_or_default()
            .chars()
            .filter(char::is_ascii_alphanumeric)
            .take(8)
            .map(|c| c.to_ascii_lowercase())
            .collect();
        // A prefix and at most 8 alphanumerics always form a valid single label.
        Self(if short.is_empty() {
            "hardened".to_owned()
        } else {
            format!("hardened-{short}")
        })
    }

    /// The first label.
    pub fn short(&self) -> &str {
        self.0.split('.').next().unwrap_or(&self.0)
    }
}

validated_string!(
    /// Workload name, doubling as containerd ID, snapshot key, cgroup and log file name:
    /// 1-63 lowercase alphanumerics or '-', not starting with '-'.
    WorkloadName,
    "workload name",
    |name| {
        if (1..=63).contains(&name.len())
            && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !name.starts_with('-')
        {
            Ok(())
        } else {
            Err("must be 1-63 lowercase alphanumerics or '-', not starting with '-'")
        }
    }
);

validated_string!(
    /// Kernel module name: alphanumerics, '_' or '-' (`modules.dep` treats both as equivalent).
    ModuleName,
    "kernel module name",
    |name| {
        if !name.is_empty() && name.len() <= 64 && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            Ok(())
        } else {
            Err("must be 1-64 alphanumerics, '_' or '-'")
        }
    }
);

impl ModuleName {
    /// The name `modules.dep` uses: dashes replaced by underscores.
    pub fn canonical(&self) -> String {
        self.0.replace('-', "_")
    }
}

validated_string!(
    /// Sysctl key, e.g. `net.ipv4.ip_forward`: dot-separated non-empty components that cannot
    /// escape `/proc/sys`.
    SysctlKey,
    "sysctl key",
    |key| {
        let valid = |part: &str| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '*'))
        };
        if key.split('.').all(valid) { Ok(()) } else { Err("must be dot-separated alphanumeric components") }
    }
);

impl SysctlKey {
    /// Path of the key under `/proc/sys`.
    pub fn proc_path(&self) -> std::path::PathBuf {
        Path::new("/proc/sys").join(self.0.replace('.', "/"))
    }
}

/// Image reference, normalized when parsed: `nginx` becomes `docker.io/library/nginx:latest`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImageRef(String);

impl ImageRef {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for ImageRef {
    type Error = InvalidValue;

    fn try_from(reference: String) -> Result<Self, Self::Error> {
        let reject = |reason| InvalidValue::new("image reference", &reference, reason);
        if reference.is_empty() || reference.len() > 512 {
            return Err(reject("must be 1 to 512 characters"));
        }
        if reference.chars().any(|c| c.is_whitespace() || c.is_control()) {
            return Err(reject("must not contain whitespace"));
        }
        if reference.starts_with(['/', ':', '@']) || reference.ends_with(['/', ':', '@']) {
            return Err(reject("is malformed"));
        }
        Ok(Self(normalize_reference(&reference)))
    }
}

impl FromStr for ImageRef {
    type Err = InvalidValue;

    fn from_str(reference: &str) -> Result<Self, Self::Err> {
        Self::try_from(reference.to_owned())
    }
}

impl From<ImageRef> for String {
    fn from(value: ImageRef) -> Self {
        value.0
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Docker-style normalization: default registry `docker.io`, `library/` for official images,
/// tag `latest` when neither a tag nor a digest is given.
fn normalize_reference(reference: &str) -> String {
    let (name, digest) = match reference.split_once('@') {
        Some((name, digest)) => (name, Some(digest)),
        None => (reference, None),
    };
    let mut name = match name.split_once('/') {
        Some((domain, _)) if domain.contains(['.', ':']) || domain == "localhost" => name.to_owned(),
        Some(_) => format!("docker.io/{name}"),
        None => format!("docker.io/library/{name}"),
    };
    if let Some(path) = name.strip_prefix("docker.io/")
        && !path.contains('/')
    {
        name = format!("docker.io/library/{path}");
    }
    let last = name.rsplit('/').next().unwrap_or_default();
    match digest {
        Some(digest) => format!("{name}@{digest}"),
        None if last.contains(':') => name,
        None => format!("{name}:latest"),
    }
}

validated_string!(
    /// Absolute, normalized host path below `/var`, the only persistent writable location.
    VarPath,
    "host path",
    |path| check_absolute(path).and_then(|()| {
        if path.strip_prefix("/var/").is_some_and(|rest| !rest.is_empty()) { Ok(()) } else { Err("must be below /var") }
    })
);

validated_string!(
    /// Absolute, normalized path inside a container.
    ContainerPath,
    "container path",
    check_absolute
);

fn check_absolute(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("must be absolute");
    }
    // Raw segments: `Path::components` would silently normalize `.` and `//` away.
    let denormalized = path != "/"
        && path
            .split('/')
            .skip(1)
            .any(|segment| matches!(segment, "" | "." | ".."));
    if denormalized || path.contains('\0') {
        return Err("must be normalized (no '.', '..' or '//')");
    }
    Ok(())
}

/// Decodes standard base64, ignoring whitespace (line breaks of `base64` output included).
pub(crate) fn decode_base64(text: &[u8]) -> Option<Vec<u8>> {
    let compact: Vec<u8> = text.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(compact).ok()
}

/// The PEM text of a base64-encoded settings value (Bottlerocket encodes PEM that way).
fn pem_from_base64(kind: &'static str, encoded: &str) -> Result<String, InvalidValue> {
    let bytes =
        decode_base64(encoded.as_bytes()).ok_or_else(|| InvalidValue::new(kind, "<base64>", "is not base64"))?;
    String::from_utf8(bytes).map_err(|_| InvalidValue::new(kind, "<base64>", "does not decode to PEM text"))
}

/// One or more PEM certificates (a chain or a CA bundle), checked to decode. Base64-encoded in
/// settings.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Certificates(String);

impl Certificates {
    const KIND: &str = "certificate PEM";

    pub fn from_pem(pem: String) -> Result<Self, InvalidValue> {
        let reject = |reason| InvalidValue::new(Self::KIND, "<pem>", reason);
        let mut count = 0;
        for cert in CertificateDer::pem_slice_iter(pem.as_bytes()) {
            cert.map_err(|_| reject("cannot be decoded"))?;
            count += 1;
        }
        if count == 0 {
            return Err(reject("contains no certificate"));
        }
        Ok(Self(pem))
    }

    pub fn pem(&self) -> &str {
        &self.0
    }
}

/// From the base64 of the PEM text.
impl TryFrom<String> for Certificates {
    type Error = InvalidValue;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        Self::from_pem(pem_from_base64(Self::KIND, &encoded)?)
    }
}

/// To the base64 of the PEM text.
impl From<Certificates> for String {
    fn from(value: Certificates) -> Self {
        base64::engine::general_purpose::STANDARD.encode(value.0)
    }
}

impl fmt::Debug for Certificates {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Certificates(..)")
    }
}

/// A PEM private key, checked to decode. Base64-encoded in settings. Never displayed, logged or
/// serialized: its `Debug` and `Serialize` implementations print `<redacted>`, so settings can be
/// exposed safely.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct PrivateKey(String);

impl PrivateKey {
    pub const REDACTED: &str = "<redacted>";
    const KIND: &str = "private key PEM";

    pub fn from_pem(pem: String) -> Result<Self, InvalidValue> {
        PrivateKeyDer::from_pem_slice(pem.as_bytes())
            .map_err(|_| InvalidValue::new(Self::KIND, "<pem>", "cannot be decoded"))?;
        Ok(Self(pem))
    }

    /// The PEM text, to hand to the TLS server. The only way to read the key.
    pub fn expose_pem(&self) -> &str {
        &self.0
    }
}

/// From the base64 of the PEM text.
impl TryFrom<String> for PrivateKey {
    type Error = InvalidValue;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        Self::from_pem(pem_from_base64(Self::KIND, &encoded)?)
    }
}

impl Serialize for PrivateKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(Self::REDACTED)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(Self::REDACTED)
    }
}

/// A SHA-256 content digest, written `sha256:<hex>` (OCI descriptors, layer diff IDs).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of(data: &[u8]) -> Self {
        Self(Sha256::digest(data).into())
    }

    /// The OCI chain ID of a layer stack: `chain(n) = sha256(chain(n-1) + " " + diff_id(n))`.
    pub fn chain_id(diff_ids: &[Digest]) -> Option<Self> {
        let (first, rest) = diff_ids.split_first()?;
        Some(rest.iter().fold(*first, |chain, diff_id| {
            Self::of(format!("{chain} {diff_id}").as_bytes())
        }))
    }
}

impl FromStr for Digest {
    type Err = InvalidValue;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let reject = |reason| InvalidValue::new("digest", value, reason);
        let hex = value
            .strip_prefix("sha256:")
            .ok_or_else(|| reject("only sha256 digests are supported"))?;
        let mut bytes = [0; 32];
        hex::decode_to_slice(hex, &mut bytes).map_err(|_| reject("must be 64 hex characters"))?;
        Ok(Self(bytes))
    }
}

impl TryFrom<String> for Digest {
    type Error = InvalidValue;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl From<Digest> for String {
    fn from(value: Digest) -> Self {
        value.to_string()
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", hex::encode(self.0))
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames() {
        assert!("a-b.example.com".parse::<Hostname>().is_ok());
        for bad in ["", "-a", "a-", "a..b", "a_b", &"a".repeat(64)] {
            assert!(bad.parse::<Hostname>().is_err(), "{bad:?}");
        }
        assert_eq!(
            Hostname::sanitize("Web-1.Example.COM.").unwrap().as_str(),
            "web-1.example.com"
        );
        assert_eq!(
            Hostname::sanitize("ip-10-0-0-1.ec2.internal other.name")
                .unwrap()
                .short(),
            "ip-10-0-0-1"
        );
        assert_eq!(Hostname::sanitize("host.under_score.example").unwrap().as_str(), "host");
        assert_eq!(Hostname::sanitize("   "), None);
        for constructed in [
            Hostname::localhost(),
            Hostname::from_instance_id(None),
            Hostname::from_instance_id(Some("i-0ABCdef1234567890")),
            Hostname::from_instance_id(Some("--..--")),
        ] {
            assert_eq!(constructed.as_str().parse::<Hostname>().unwrap(), constructed);
        }
        assert_eq!(
            Hostname::from_instance_id(Some("i-0ABCdef1234567890")).as_str(),
            "hardened-i0abcdef"
        );
        assert_eq!(Hostname::from_instance_id(Some("")).as_str(), "hardened");
    }

    #[test]
    fn workload_and_module_names() {
        assert!("web-1".parse::<WorkloadName>().is_ok());
        for bad in ["", "Web", "-web", "a/b", &"a".repeat(64)] {
            assert!(bad.parse::<WorkloadName>().is_err(), "{bad:?}");
        }
        assert_eq!("mlx5-core".parse::<ModuleName>().unwrap().canonical(), "mlx5_core");
        assert!("../evil".parse::<ModuleName>().is_err());
    }

    #[test]
    fn sysctl_keys_stay_in_proc_sys() {
        let key: SysctlKey = "net.ipv4.ip_forward".parse().unwrap();
        assert_eq!(key.proc_path(), Path::new("/proc/sys/net/ipv4/ip_forward"));
        for bad in ["", "net..x", "net./x", "../x", "a.b c"] {
            assert!(bad.parse::<SysctlKey>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn image_references_are_normalized() {
        for (reference, expected) in [
            ("nginx", "docker.io/library/nginx:latest"),
            ("nginx:1.29", "docker.io/library/nginx:1.29"),
            ("docker.io/nginx", "docker.io/library/nginx:latest"),
            ("user/app", "docker.io/user/app:latest"),
            ("ghcr.io/org/app:v1", "ghcr.io/org/app:v1"),
            ("localhost/app", "localhost/app:latest"),
            ("registry:5000/app", "registry:5000/app:latest"),
            ("registry:5000/app:2", "registry:5000/app:2"),
            ("busybox@sha256:abcd", "docker.io/library/busybox@sha256:abcd"),
        ] {
            assert_eq!(reference.parse::<ImageRef>().unwrap().as_str(), expected, "{reference}");
        }
        for bad in ["", "a b", "nginx:", "/nginx"] {
            assert!(bad.parse::<ImageRef>().is_err(), "{bad:?}");
        }
        let normalized: ImageRef = "nginx".parse().unwrap();
        assert_eq!(
            normalized.as_str().parse::<ImageRef>().unwrap(),
            normalized,
            "normalization is idempotent"
        );
    }

    #[test]
    fn paths() {
        assert!("/var/lib/web".parse::<VarPath>().is_ok());
        for bad in ["/var", "/var/", "/etc", "/var/../etc", "var/lib", "/var//x", "/var/./x"] {
            assert!(bad.parse::<VarPath>().is_err(), "{bad:?}");
        }
        assert!("/data".parse::<ContainerPath>().is_ok());
        assert!("data".parse::<ContainerPath>().is_err());
    }

    #[test]
    fn pem_material() {
        use base64::engine::general_purpose::STANDARD;
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec!["x".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let certs = Certificates::try_from(STANDARD.encode(cert.pem())).unwrap();
        assert_eq!(certs.pem(), cert.pem());
        assert_eq!(
            String::from(certs),
            STANDARD.encode(cert.pem()),
            "serializes back to base64"
        );
        // `base64` wraps its output at 76 columns.
        let wrapped: String = STANDARD
            .encode(cert.pem())
            .as_bytes()
            .chunks(76)
            .map(|line| format!("{}\n", std::str::from_utf8(line).unwrap()))
            .collect();
        assert!(Certificates::try_from(wrapped).is_ok());
        assert!(Certificates::try_from(cert.pem()).is_err(), "raw PEM is not base64");
        assert!(Certificates::try_from(STANDARD.encode("garbage")).is_err());
        assert!(
            Certificates::try_from(STANDARD.encode(key.serialize_pem())).is_err(),
            "a key is not a certificate"
        );

        assert!(
            PrivateKey::try_from(key.serialize_pem()).is_err(),
            "raw PEM is not base64"
        );
        let key = PrivateKey::try_from(STANDARD.encode(key.serialize_pem())).unwrap();
        assert_eq!(format!("{key:?}"), "<redacted>");
        assert_eq!(serde_json::to_string(&key).unwrap(), "\"<redacted>\"");
        assert!(PrivateKey::try_from(STANDARD.encode(PrivateKey::REDACTED)).is_err());
    }

    #[test]
    fn domain_names() {
        assert!("corp.example.com".parse::<DomainName>().is_ok());
        for bad in ["", "a b", "a..b", "-a.com", "a\nnameserver 1.2.3.4"] {
            assert!(bad.parse::<DomainName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn digests_and_chain_ids() {
        let d = |c: char| {
            format!("sha256:{}", c.to_string().repeat(64))
                .parse::<Digest>()
                .unwrap()
        };
        assert_eq!(Digest::chain_id(&[]), None);
        assert_eq!(Digest::chain_id(&[d('a')]), Some(d('a')));
        // printf 'sha256:aa…a sha256:bb…b' | sha256sum
        assert_eq!(
            Digest::chain_id(&[d('a'), d('b')]).unwrap().to_string(),
            "sha256:ccd722928bd92476ba1745586fed6e45a102504185ad88cd89e01ff116fd146c"
        );
        assert_eq!(
            Digest::chain_id(&[d('a'), d('b'), d('c')]).unwrap().to_string(),
            "sha256:c1377126441fb2f5ec2c21ae2a60255331d639e830f0ee1b40a36e52d4c40588"
        );
        assert!("sha512:00".parse::<Digest>().is_err());
        assert!("sha256:zz".parse::<Digest>().is_err());
    }
}

//! Container image references.

use std::fmt;
use std::str::FromStr;

use controllers_helpers::InvalidValue;
use serde::{Deserialize, Serialize};

/// Image reference, normalized when parsed: `nginx` becomes `docker.io/library/nginx:latest`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ImageRef(String);

impl ImageRef {
    /// The normalized reference.
    #[must_use]
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
        if reference
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        {
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
#[must_use]
fn normalize_reference(reference: &str) -> String {
    let (name, digest) = match reference.split_once('@') {
        Some((name, digest)) => (name, Some(digest)),
        None => (reference, None),
    };
    let mut name = match name.split_once('/') {
        Some((domain, _)) if domain.contains(['.', ':']) || domain == "localhost" => {
            name.to_owned()
        }
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

#[cfg(test)]
mod tests {
    use super::*;

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
            (
                "busybox@sha256:abcd",
                "docker.io/library/busybox@sha256:abcd",
            ),
        ] {
            assert_eq!(
                reference.parse::<ImageRef>().unwrap().as_str(),
                expected,
                "{reference}"
            );
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
}

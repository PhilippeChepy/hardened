//! `[settings.kubernetes.static-pods.<name>]`: pods kubelet runs from files.

use std::collections::BTreeMap;

use controllers_helpers::InvalidValue;
use controllers_helpers::base64_text;
use serde::{Deserialize, Serialize};

/// `[settings.kubernetes.static-pods.<name>]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct StaticPod {
    /// When false, the pod is declared but kubelet does not run it.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// The pod.
    pub manifest: PodManifest,
}

fn yes() -> bool {
    true
}

/// A Pod manifest, YAML or JSON; base64-encoded in settings.
///
/// Checked without a YAML parser: a JSON manifest is parsed, a YAML one only scanned at its top
/// level (one document, `apiVersion: v1`, `kind: Pod`, `metadata`). That catches a manifest of the
/// wrong kind or a non-manifest; kubelet validates the rest, and reports it in its log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PodManifest(String);

impl PodManifest {
    const KIND: &str = "static pod manifest";

    /// From the manifest's text.
    pub(crate) fn from_text(text: String) -> Result<Self, InvalidValue> {
        match Self::check(&text) {
            Ok(()) => Ok(Self(text)),
            Err(reason) => Err(InvalidValue::new(Self::KIND, "<manifest>", reason)),
        }
    }

    /// The manifest's text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.0
    }

    fn check(text: &str) -> Result<(), &'static str> {
        if text.contains('\0') {
            return Err("must not contain NUL bytes");
        }
        let (api_version, kind, has_metadata) = if text.trim_start().starts_with('{') {
            let manifest: serde_json::Value =
                serde_json::from_str(text).map_err(|_| "is not valid JSON")?;
            let field = |key: &str| {
                manifest
                    .get(key)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            (
                field("apiVersion"),
                field("kind"),
                manifest.get("metadata").is_some_and(|m| m.is_object()),
            )
        } else {
            let keys = yaml_top_level(text)?;
            let field = |key: &str| keys.get(key).map(|value| (*value).to_owned());
            (
                field("apiVersion"),
                field("kind"),
                keys.contains_key("metadata"),
            )
        };
        match (api_version.as_deref(), kind.as_deref()) {
            (Some("v1"), Some("Pod")) if has_metadata => Ok(()),
            (Some("v1"), Some("Pod")) => Err("has no metadata"),
            _ => Err("must be a Pod (apiVersion: v1, kind: Pod)"),
        }
    }
}

/// The top-level `key: value` pairs of a YAML mapping document (a nested value is empty).
fn yaml_top_level(text: &str) -> Result<BTreeMap<&str, &str>, &'static str> {
    let mut keys = BTreeMap::new();
    for line in text.lines() {
        let content = line.trim_end();
        if content.is_empty() || content.starts_with('#') {
            continue;
        }
        if content == "---" || content == "..." {
            if keys.is_empty() {
                continue;
            }
            return Err("must hold a single YAML document");
        }
        // Lines of nested values (indented, or block sequence items).
        if line.starts_with([' ', '\t', '-']) {
            if keys.is_empty() {
                return Err("must be a YAML mapping");
            }
            continue;
        }
        let (key, value) = content.split_once(':').ok_or("must be a YAML mapping")?;
        let value = value.split(" #").next().unwrap_or_default().trim();
        let value = value.trim_matches(|c| c == '"' || c == '\'');
        if keys.insert(key.trim(), value).is_some() {
            return Err("has a key twice");
        }
    }
    Ok(keys)
}

/// From the base64 of the manifest.
impl TryFrom<String> for PodManifest {
    type Error = InvalidValue;

    fn try_from(encoded: String) -> Result<Self, Self::Error> {
        let reject = |reason| InvalidValue::new(Self::KIND, "<base64>", reason);
        let bytes =
            base64_text::decode(encoded.as_bytes()).ok_or_else(|| reject("is not base64"))?;
        let text = String::from_utf8(bytes).map_err(|_| reject("is not UTF-8 text"))?;
        Self::from_text(text)
    }
}

/// To the base64 of the manifest.
impl From<PodManifest> for String {
    fn from(manifest: PodManifest) -> Self {
        base64_text::encode(manifest.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest(text: &str) -> Result<PodManifest, InvalidValue> {
        PodManifest::try_from(base64_text::encode(text))
    }

    #[test]
    fn pod_manifests() {
        let yaml = "# A static pod.\n---\napiVersion: v1\nkind: \"Pod\"  # quoted\nmetadata:\n  \
                    name: web\nspec:\n  containers:\n  - name: web\n    image: nginx\n    \
                    args: |\n      kind: Deployment\n";
        assert_eq!(manifest(yaml).unwrap().text(), yaml);
        let json =
            r#"{"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "web"}, "spec": {}}"#;
        assert!(manifest(json).is_ok());
        assert_eq!(
            String::from(manifest(json).unwrap()),
            base64_text::encode(json),
            "serializes back to base64"
        );
        for (bad, why) in [
            (
                "apiVersion: apps/v1\nkind: Deployment\nmetadata: {}\n",
                "a Deployment",
            ),
            ("apiVersion: v1\nkind: Pod\n", "no metadata"),
            (
                "apiVersion: v1\nkind: Pod\nmetadata: {}\n---\napiVersion: v1\nkind: Pod\n",
                "two documents",
            ),
            (
                "apiVersion: v1\nkind: Pod\nkind: Pod\nmetadata: {}\n",
                "a key twice",
            ),
            ("- apiVersion: v1\n", "a sequence"),
            ("just text\n", "not a mapping"),
            (r#"{"apiVersion": "v1", "kind": "Pod""#, "truncated JSON"),
            (
                r#"{"apiVersion": "v1", "kind": "Service", "metadata": {}}"#,
                "a JSON Service",
            ),
        ] {
            assert!(manifest(bad).is_err(), "{why} accepted");
        }
        assert!(PodManifest::try_from("not base64!".to_owned()).is_err());
    }
}

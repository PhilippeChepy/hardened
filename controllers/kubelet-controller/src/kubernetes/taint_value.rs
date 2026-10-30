//! Node taints, as Bottlerocket writes them.

use controllers_helpers::InvalidValue;
use serde::{Deserialize, Serialize};

use super::labels::LabelValue;

/// A taint's value and effect, written `<value>:<effect>` (Bottlerocket's form); the value may
/// be empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct TaintValue {
    /// Possibly empty.
    pub value: LabelValue,
    /// What the taint does to pods not tolerating it.
    pub effect: TaintEffect,
}

/// What a taint does to pods not tolerating it.
#[allow(missing_docs, reason = "Kubernetes' names, self-explanatory")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaintEffect {
    NoSchedule,
    PreferNoSchedule,
    NoExecute,
}

impl TaintEffect {
    /// Kubernetes' name of the effect.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoSchedule => "NoSchedule",
            Self::PreferNoSchedule => "PreferNoSchedule",
            Self::NoExecute => "NoExecute",
        }
    }
}

impl TryFrom<String> for TaintValue {
    type Error = InvalidValue;

    fn try_from(text: String) -> Result<Self, Self::Error> {
        let reject = |reason| InvalidValue::new("taint", &text, reason);
        let (value, effect) = text
            .rsplit_once(':')
            .ok_or_else(|| reject("must be <value>:<effect>"))?;
        let effect = match effect {
            "NoSchedule" => TaintEffect::NoSchedule,
            "PreferNoSchedule" => TaintEffect::PreferNoSchedule,
            "NoExecute" => TaintEffect::NoExecute,
            _ => {
                return Err(reject(
                    "its effect must be NoSchedule, PreferNoSchedule or NoExecute",
                ));
            }
        };
        Ok(Self {
            value: LabelValue::try_from(value.to_owned())?,
            effect,
        })
    }
}

impl From<TaintValue> for String {
    fn from(taint: TaintValue) -> Self {
        format!("{}:{}", taint.value, taint.effect.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn taints() {
        let taint = TaintValue::try_from("gpu:NoSchedule".to_owned()).unwrap();
        assert_eq!(
            (taint.value.as_str(), taint.effect),
            ("gpu", TaintEffect::NoSchedule)
        );
        let empty = TaintValue::try_from(":NoExecute".to_owned()).unwrap();
        assert_eq!(empty.value.as_str(), "");
        assert_eq!(String::from(empty), ":NoExecute");
        for bad in ["gpu", "gpu:Never", "a b:NoSchedule"] {
            assert!(TaintValue::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }
}

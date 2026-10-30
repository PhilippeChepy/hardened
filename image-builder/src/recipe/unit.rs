//! A component of a target: what the pipeline builds.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use anyhow::Context;

use crate::recipe::ComponentName;

/// A component of a target, which the pipeline builds: `<target>/<component>`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Unit {
    /// The target building it.
    pub target: ComponentName,
    /// The component.
    pub component: ComponentName,
}

impl FromStr for Unit {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> anyhow::Result<Self> {
        let (target, component) = text
            .split_once('/')
            .with_context(|| format!("{text:?} is not `<target>/<component>`"))?;
        Ok(Self {
            target: target.parse()?,
            component: component.parse()?,
        })
    }
}

impl Display for Unit {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.target, self.component)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_units() {
        let unit: Unit = "tools/perl".parse().unwrap();
        assert_eq!(
            (unit.target.as_str(), unit.component.as_str()),
            ("tools", "perl")
        );
        assert_eq!(unit.to_string(), "tools/perl");
        for bad in ["perl", "tools/", "/perl", "tools/a/b", "Tools/perl"] {
            assert!(bad.parse::<Unit>().is_err(), "{bad:?} accepted");
        }
    }
}

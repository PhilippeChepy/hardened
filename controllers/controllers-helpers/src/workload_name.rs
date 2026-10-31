//! Workload names, and the service and container names a workload takes from its name.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::str::FromStr;

use libserviced::definition::ServiceName;
use serde::{Deserialize, Serialize};

use crate::InvalidValue;

/// A workload's service, and its containerd container, are named `workload-<name>`.
const PREFIX: &str = "workload-";

/// A workload's name: 1-63 lowercase alphanumerics separated by single '-'. Its service and
/// container name, `workload-<name>`, is then one serviced (up to 128 lowercase alphanumerics,
/// '-', '_' and '.') and containerd (up to 76 alphanumerics separated by single '.', '_' or '-')
/// accept, made once, when the name is parsed: [`WorkloadName::service_name`] and
/// [`WorkloadName::container_id`] cannot fail.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct WorkloadName {
    service: ServiceName,
}

impl WorkloadName {
    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        let service = self.service.as_str();
        service.strip_prefix(PREFIX).unwrap_or(service)
    }

    /// The name of the service running the workload.
    #[must_use]
    pub fn service_name(&self) -> &ServiceName {
        &self.service
    }

    /// The containerd ID of the workload's container: its service's name.
    #[must_use]
    pub fn container_id(&self) -> &str {
        self.service.as_str()
    }

    /// The workload a service runs, by the service's name; `None` for other services.
    #[must_use]
    pub fn from_service_name(service: &str) -> Option<Self> {
        service.strip_prefix(PREFIX)?.parse().ok()
    }
}

impl TryFrom<String> for WorkloadName {
    type Error = InvalidValue;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        const REASON: &str = "must be 1-63 lowercase alphanumerics, separated by single '-'";
        let words = name.split('-').all(|word| {
            !word.is_empty()
                && word
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        });
        if name.len() > 63 || !words {
            return Err(InvalidValue::new("workload name", &name, REASON));
        }
        let service = ServiceName::try_from(format!("{PREFIX}{name}"))
            .map_err(|_| InvalidValue::new("workload name", &name, REASON))?;
        Ok(Self { service })
    }
}

impl FromStr for WorkloadName {
    type Err = InvalidValue;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::try_from(name.to_owned())
    }
}

impl From<WorkloadName> for String {
    fn from(name: WorkloadName) -> Self {
        name.as_str().to_owned()
    }
}

impl fmt::Display for WorkloadName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// Equality, ordering and hashing are the name's, as `Borrow<str>` requires.
impl PartialEq for WorkloadName {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for WorkloadName {}

impl PartialOrd for WorkloadName {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WorkloadName {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl Hash for WorkloadName {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

impl Borrow<str> for WorkloadName {
    fn borrow(&self) -> &str {
        self.as_str()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_names() {
        for good in ["web-1", "a", "a-b-c", &"a".repeat(63)] {
            assert!(good.parse::<WorkloadName>().is_ok(), "{good:?}");
        }
        for bad in [
            "",
            "Web",
            "-web",
            "web-",
            "a--b",
            "a/b",
            "a_b",
            &"a".repeat(64),
        ] {
            assert!(bad.parse::<WorkloadName>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn names_its_service_and_container() {
        let name: WorkloadName = "web".parse().unwrap();
        assert_eq!(name.as_str(), "web");
        assert_eq!(name.service_name().as_str(), "workload-web");
        assert_eq!(name.container_id(), "workload-web");
        assert_eq!(
            WorkloadName::from_service_name("workload-web"),
            Some(name.clone())
        );
        assert_eq!(WorkloadName::from_service_name("containerd"), None);
        assert_eq!(WorkloadName::from_service_name("workload-"), None);
        assert_eq!(String::from(name.clone()), "web");
        assert_eq!(serde_json::to_string(&name).unwrap(), "\"web\"");
        let back: WorkloadName = serde_json::from_str("\"web\"").unwrap();
        assert_eq!(back, name);
    }

    /// The longest name gives a container ID containerd accepts: at most 76 characters.
    #[test]
    fn the_longest_name_fits_containerd() {
        let longest: WorkloadName = "a".repeat(63).parse().unwrap();
        assert!(longest.container_id().len() <= 76);
    }
}

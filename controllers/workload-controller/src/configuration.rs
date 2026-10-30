//! What machine-controller configured: user-data's workloads, which run whether kubelet does or
//! not. Kept in [`STATE`] so a restarted workload-controller knows it without being configured
//! again.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::ErrorKind;
use std::path::Path;

use controllers_helpers::InvalidMessage;
use controllers_helpers::WorkloadName;
use controllers_helpers::atomic_file;
use controllers_helpers::invalid_message::WithinResult;
use serde::Deserialize;
use serde::Serialize;
use workload_controller::ContainerSettings;
use workload_controller::workload;

/// Where the last configuration is kept.
pub const STATE: &str = "/run/workload-controller/state.json";

/// The configuration of `WorkloadController.Configure`, validated: `settings.hardened.containers`,
/// disabled ones included (they own their names).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Configuration {
    workloads: BTreeMap<WorkloadName, ContainerSettings>,
}

impl TryFrom<workload::Configuration> for Configuration {
    type Error = InvalidMessage;

    fn try_from(message: workload::Configuration) -> Result<Self, Self::Error> {
        let mut workloads = BTreeMap::new();
        for (index, declared) in message.workloads.into_iter().enumerate() {
            let at = format!("workloads[{index}]");
            let (name, settings) = ContainerSettings::try_from_proto(declared).within(&at)?;
            if workloads.insert(name, settings).is_some() {
                return Err(InvalidMessage::new("name", "is declared twice").within(&at));
            }
        }
        Ok(Self { workloads })
    }
}

impl Configuration {
    /// User-data's workloads.
    pub fn workloads(&self) -> impl Iterator<Item = (&WorkloadName, &ContainerSettings)> {
        self.workloads.iter()
    }

    /// Whether user-data declares the workload `name`.
    #[must_use]
    pub fn declares(&self, name: &WorkloadName) -> bool {
        self.workloads.contains_key(name)
    }

    /// The configuration kept in `path`; `None` before the first one.
    ///
    /// # Errors
    ///
    /// When the file cannot be read or parsed.
    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Keeps the configuration in `path`, replaced atomically. Readable by root only: workloads'
    /// environments often hold credentials.
    ///
    /// # Errors
    ///
    /// When the file cannot be written.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        atomic_file::write(path, &serde_json::to_vec_pretty(self)?, 0o600)
    }
}

#[cfg(test)]
mod tests {
    use workload_controller::workloads;

    use super::*;
    use crate::service_file::tests::declared;

    fn containers(workloads: Vec<workloads::DeclaredWorkload>) -> workload::Configuration {
        workload::Configuration { workloads }
    }

    #[test]
    fn converts_the_message() {
        let configuration = Configuration::try_from(containers(vec![
            declared("web", true),
            declared("off", false),
        ]))
        .unwrap();
        assert!(configuration.declares(&"off".parse().unwrap()));
        assert!(configuration.workloads[&"web".parse::<WorkloadName>().unwrap()].enabled);
        assert_eq!(
            Configuration::try_from(containers(Vec::new())).unwrap(),
            Configuration::default()
        );
    }

    #[test]
    fn rejects_invalid_messages() {
        let mut bad_name = declared("web", true);
        bad_name.name = "Web".into();
        for (message, field) in [
            (containers(vec![bad_name]), "workloads[0].name"),
            (
                containers(vec![declared("web", true), declared("web", false)]),
                "workloads[1].name",
            ),
        ] {
            let error = Configuration::try_from(message).unwrap_err();
            assert_eq!(error.field(), field, "{error}");
        }
    }

    #[test]
    fn round_trips_through_its_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state.json");
        assert_eq!(Configuration::load(&path).unwrap(), None);
        let configuration = Configuration::try_from(containers(vec![
            declared("web", true),
            declared("off", false),
        ]))
        .unwrap();
        configuration.save(&path).unwrap();
        configuration.save(&path).unwrap();
        assert_eq!(Configuration::load(&path).unwrap(), Some(configuration));
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}

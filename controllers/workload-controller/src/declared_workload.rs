//! User-data's workloads as `hardened.workloads.v1.DeclaredWorkload`, and workload-controller's
//! configuration.

use std::collections::BTreeMap;

use controllers_helpers::InvalidMessage;
use controllers_helpers::WorkloadName;
use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::{FieldResult, WithinResult};

use crate::workload;
use crate::workloads;
use crate::{ContainerSettings, ImageWorkload};

/// Methods rather than `From` and `TryFrom`: the name is not part of [`ContainerSettings`] (it
/// keys them), and the orphan rule forbids implementing those traits for a tuple.
impl ContainerSettings {
    /// The message declaring the workload `name`.
    #[must_use]
    pub fn into_proto(self, name: WorkloadName) -> workloads::DeclaredWorkload {
        workloads::DeclaredWorkload {
            name: name.into(),
            enabled: self.enabled,
            spec: Some(self.workload.into()),
        }
    }

    /// The workload a message declares, and its name.
    pub fn try_from_proto(
        message: workloads::DeclaredWorkload,
    ) -> Result<(WorkloadName, Self), InvalidMessage> {
        let name = WorkloadName::try_from(message.name).field("name")?;
        let spec = invalid_message::required(message.spec, "spec")?;
        let settings = Self {
            enabled: message.enabled,
            workload: ImageWorkload::try_from(spec).within("spec")?,
        };
        Ok((name, settings))
    }
}

impl From<BTreeMap<WorkloadName, ContainerSettings>> for workloads::DeclaredWorkloads {
    fn from(containers: BTreeMap<WorkloadName, ContainerSettings>) -> Self {
        Self {
            workloads: containers
                .into_iter()
                .map(|(name, container)| container.into_proto(name))
                .collect(),
        }
    }
}

impl From<BTreeMap<WorkloadName, ContainerSettings>> for workload::Configuration {
    fn from(containers: BTreeMap<WorkloadName, ContainerSettings>) -> Self {
        Self {
            workloads: workloads::DeclaredWorkloads::from(containers).workloads,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workload_spec::tests::full_workload;

    #[test]
    fn round_trips() {
        let name: WorkloadName = "web".parse().unwrap();
        for enabled in [true, false] {
            let settings = ContainerSettings {
                enabled,
                workload: full_workload(),
            };
            let message = settings.clone().into_proto(name.clone());
            assert_eq!(
                ContainerSettings::try_from_proto(message).unwrap(),
                (name.clone(), settings)
            );
        }
    }

    #[test]
    fn rejects_invalid_declarations() {
        let valid = ContainerSettings {
            enabled: true,
            workload: full_workload(),
        }
        .into_proto("web".parse().unwrap());
        let mut bad_spec = valid.clone();
        bad_spec.spec.as_mut().unwrap().mounts[0].source = "/etc".to_owned();
        for (message, field) in [
            (
                workloads::DeclaredWorkload {
                    name: "Web".to_owned(),
                    ..valid.clone()
                },
                "name",
            ),
            (
                workloads::DeclaredWorkload {
                    spec: None,
                    ..valid.clone()
                },
                "spec",
            ),
            (bad_spec, "spec.mounts[0].source"),
        ] {
            let error = ContainerSettings::try_from_proto(message).unwrap_err();
            assert_eq!(error.field(), field);
        }
    }
}

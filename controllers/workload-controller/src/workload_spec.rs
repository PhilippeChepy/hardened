//! Image workloads as `hardened.workloads.v1.WorkloadSpec`.

use std::collections::BTreeMap;

use controllers_helpers::Argument;
use controllers_helpers::InvalidMessage;
use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::{FieldResult, WithinResult};

use crate::workloads;
use crate::{
    ContainerPath, EnvName, EnvValue, ImageRef, ImageWorkload, MountSettings, Privileges,
    RestartPolicy, VarPath,
};

impl From<RestartPolicy> for workloads::RestartPolicy {
    fn from(restart: RestartPolicy) -> Self {
        match restart {
            RestartPolicy::Always => Self::Always,
            RestartPolicy::OnFailure => Self::OnFailure,
            RestartPolicy::Never => Self::Never,
        }
    }
}

impl From<MountSettings> for workloads::Mount {
    fn from(mount: MountSettings) -> Self {
        Self {
            source: mount.source.into(),
            destination: mount.destination.into(),
            read_only: mount.read_only,
        }
    }
}

impl TryFrom<workloads::Mount> for MountSettings {
    type Error = InvalidMessage;

    fn try_from(message: workloads::Mount) -> Result<Self, Self::Error> {
        Ok(Self {
            source: VarPath::try_from(message.source).field("source")?,
            destination: ContainerPath::try_from(message.destination).field("destination")?,
            read_only: message.read_only,
        })
    }
}

impl From<ImageWorkload> for workloads::WorkloadSpec {
    fn from(workload: ImageWorkload) -> Self {
        Self {
            image: workload.image.into(),
            command: workload.command.into_iter().map(String::from).collect(),
            env: workload
                .env
                .into_iter()
                .map(|(name, value)| (name.into(), value.into()))
                .collect(),
            privileged: match workload.privileged {
                Privileges::Unprivileged => None,
                Privileges::Privileged { host_root } => Some(workloads::Privileged {
                    host_root: host_root.map(String::from).unwrap_or_default(),
                }),
            },
            restart: workloads::RestartPolicy::from(workload.restart).into(),
            mounts: workload
                .mounts
                .into_iter()
                .map(workloads::Mount::from)
                .collect(),
            console: workload.console,
        }
    }
}

/// An unspecified restart policy is `always`, as the API documents it.
impl TryFrom<workloads::WorkloadSpec> for ImageWorkload {
    type Error = InvalidMessage;

    fn try_from(message: workloads::WorkloadSpec) -> Result<Self, Self::Error> {
        let restart = match workloads::RestartPolicy::try_from(message.restart) {
            Ok(workloads::RestartPolicy::Unspecified | workloads::RestartPolicy::Always) => {
                RestartPolicy::Always
            }
            Ok(workloads::RestartPolicy::OnFailure) => RestartPolicy::OnFailure,
            Ok(workloads::RestartPolicy::Never) => RestartPolicy::Never,
            Err(error) => return Err(InvalidMessage::new("restart", error)),
        };
        let env = message
            .env
            .into_iter()
            .map(|(name, value)| {
                Ok((
                    EnvName::try_from(name).field("env")?,
                    EnvValue::try_from(value).field("env")?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, InvalidMessage>>()?;
        let mounts = message
            .mounts
            .into_iter()
            .enumerate()
            .map(|(index, mount)| {
                MountSettings::try_from(mount).within(&format!("mounts[{index}]"))
            })
            .collect::<Result<_, _>>()?;
        Ok(Self {
            image: ImageRef::try_from(message.image).field("image")?,
            command: invalid_message::convert_each(message.command, "command", Argument::try_from)?,
            env,
            privileged: match message.privileged {
                None => Privileges::Unprivileged,
                Some(privileged) => Privileges::Privileged {
                    host_root: match privileged.host_root.as_str() {
                        "" => None,
                        _ => Some(
                            ContainerPath::try_from(privileged.host_root)
                                .field("privileged.host_root")?,
                        ),
                    },
                },
            },
            restart,
            mounts,
            console: message.console,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// A workload with every field set.
    pub(crate) fn full_workload() -> ImageWorkload {
        ImageWorkload {
            image: "ghcr.io/org/app:v1".parse().unwrap(),
            command: ["/bin/app", "--port", "8080"]
                .map(|argument| argument.parse::<Argument>().unwrap())
                .into(),
            env: BTreeMap::from([
                ("FOO".parse().unwrap(), "bar".parse().unwrap()),
                ("EMPTY".parse().unwrap(), "".parse().unwrap()),
            ]),
            privileged: Privileges::Privileged {
                host_root: Some("/host".parse().unwrap()),
            },
            restart: RestartPolicy::OnFailure,
            mounts: vec![
                MountSettings {
                    source: "/var/lib/app".parse().unwrap(),
                    destination: "/data".parse().unwrap(),
                    read_only: true,
                },
                MountSettings {
                    source: "/var/log/app".parse().unwrap(),
                    destination: "/logs".parse().unwrap(),
                    read_only: false,
                },
            ],
            console: true,
        }
    }

    #[test]
    fn round_trips() {
        let workload = full_workload();
        let message = workloads::WorkloadSpec::from(workload.clone());
        assert_eq!(
            message.restart,
            i32::from(workloads::RestartPolicy::OnFailure)
        );
        assert_eq!(ImageWorkload::try_from(message).unwrap(), workload);
    }

    #[test]
    fn unspecified_restart_is_always() {
        let message = workloads::WorkloadSpec {
            image: "nginx".to_owned(),
            ..Default::default()
        };
        let workload = ImageWorkload::try_from(message).unwrap();
        assert_eq!(workload.restart, RestartPolicy::Always);
    }

    #[test]
    fn rejects_what_user_data_rejects() {
        let valid = workloads::WorkloadSpec::from(full_workload());
        let mut bad_mount = valid.clone();
        bad_mount.mounts[1].source = "/etc".to_owned();
        let mut comma = valid.clone();
        comma.mounts[0].destination = "/data,rw".to_owned();
        let mut nul = valid.clone();
        nul.env.insert("X".to_owned(), "a\0b".to_owned());
        let mut nul_argument = valid.clone();
        nul_argument.command[1] = "a\0b".to_owned();
        let mut bad_env = valid.clone();
        bad_env.env.insert("A=B".to_owned(), String::new());
        for (message, field, why) in [
            (
                workloads::WorkloadSpec {
                    image: String::new(),
                    ..valid.clone()
                },
                "image",
                "no image",
            ),
            (
                workloads::WorkloadSpec {
                    restart: 9,
                    ..valid.clone()
                },
                "restart",
                "an unknown restart policy",
            ),
            (bad_mount, "mounts[1].source", "a mount outside /var"),
            (comma, "mounts[0].destination", "a comma in a mount path"),
            (nul, "env", "a NUL byte in a value"),
            (nul_argument, "command[1]", "a NUL byte in an argument"),
            (bad_env, "env", "an '=' in a variable name"),
        ] {
            let error = ImageWorkload::try_from(message).expect_err(why);
            assert_eq!(error.field(), field, "{why}: {error}");
        }
    }
}

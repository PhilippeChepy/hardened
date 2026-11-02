//! The plugins' settings as messages, for `Machine.GetSettings` and nvidia-controller's
//! `Configure`.

use crate::DraSettings;
use crate::nvidia;
use crate::{
    DeviceIdStrategy, DeviceListStrategy, DevicePartitioningStrategy, DevicePluginSettings,
    DeviceSharingStrategy, Mig,
};

impl From<DevicePluginSettings> for nvidia::DevicePlugin {
    fn from(settings: DevicePluginSettings) -> Self {
        let slicing = settings.time_slicing;
        Self {
            enabled: settings.enabled,
            pass_device_specs: settings.pass_device_specs,
            device_id_strategy: match settings.device_id_strategy {
                DeviceIdStrategy::Index => nvidia::DeviceIdStrategy::Index,
                DeviceIdStrategy::Uuid => nvidia::DeviceIdStrategy::Uuid,
            }
            .into(),
            device_list_strategy: (settings.device_list_strategy.iter())
                .map(|strategy| {
                    i32::from(match strategy {
                        DeviceListStrategy::VolumeMounts => {
                            nvidia::DeviceListStrategy::VolumeMounts
                        }
                        DeviceListStrategy::Envvar => nvidia::DeviceListStrategy::Envvar,
                        DeviceListStrategy::CdiCri => nvidia::DeviceListStrategy::CdiCri,
                        DeviceListStrategy::CdiAnnotations => {
                            nvidia::DeviceListStrategy::CdiAnnotations
                        }
                    })
                })
                .collect(),
            time_slicing: (settings.device_sharing_strategy == DeviceSharingStrategy::TimeSlicing)
                .then(|| nvidia::TimeSlicing {
                    replicas: slicing.replicas.get().into(),
                    rename_by_default: slicing.rename_by_default,
                    fail_requests_greater_than_one: slicing.fail_requests_greater_than_one,
                }),
            mps: settings.mps.map(|mps| nvidia::Mps {
                replicas: mps.replicas.map(|replicas| replicas.get().into()),
            }),
            mig: settings.mig.map(nvidia::Mig::from),
            device_partitioning_strategy: match settings.device_partitioning_strategy {
                DevicePartitioningStrategy::None => nvidia::DevicePartitioningStrategy::None,
                DevicePartitioningStrategy::Mig => nvidia::DevicePartitioningStrategy::Mig,
            }
            .into(),
        }
    }
}

impl From<Mig> for nvidia::Mig {
    fn from(mig: Mig) -> Self {
        Self {
            profile: (mig.profile.into_iter())
                .map(|(model, profile)| (model.to_string(), profile.to_string()))
                .collect(),
        }
    }
}

impl TryFrom<nvidia::Mig> for Mig {
    type Error = String;

    fn try_from(mig: nvidia::Mig) -> Result<Self, Self::Error> {
        let profile = (mig.profile.into_iter())
            .map(|(model, profile)| Ok((model.try_into()?, profile.try_into()?)))
            .collect::<Result<_, String>>()?;
        Ok(Self { profile })
    }
}

impl DevicePluginSettings {
    /// nvidia-controller's configuration: the MIG profiles when the GPUs are partitioned, whether
    /// the device plugin runs or not (the DRA plugin allocates MIG instances too).
    #[must_use]
    pub fn partitioning(&self) -> nvidia::Configuration {
        nvidia::Configuration {
            mig: (self.device_partitioning_strategy == DevicePartitioningStrategy::Mig)
                .then(|| self.mig.clone().unwrap_or_default().into()),
        }
    }
}

impl From<DraSettings> for nvidia::Dra {
    fn from(settings: DraSettings) -> Self {
        Self {
            enabled: settings.enabled,
        }
    }
}

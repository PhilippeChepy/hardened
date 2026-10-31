//! The workloads serviced's services define: user-data's in the runtime layer, the API's in the
//! persistent layer.

use controllers_helpers::WorkloadName;
use libserviced::api;
use libserviced::definition::Layer;
use libserviced::definition::Service;
use workload_controller::ImageWorkload;

use crate::service_file;

/// Who defines a workload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// `settings.hardened.containers`, in the runtime layer.
    UserData,
    /// The API's `Workloads.Apply`, in the persistent layer.
    Api,
}

/// A workload, as its service defines it.
#[derive(Debug, Clone, PartialEq)]
pub struct DefinedWorkload {
    /// Its name, the service's without `workload-`.
    pub name: WorkloadName,
    pub workload: ImageWorkload,
    pub source: Source,
}

impl DefinedWorkload {
    /// The workload `service` runs; `None` for other services, and for workload services that do
    /// not define one (logged).
    #[must_use]
    fn from_service(service: &api::Service) -> Option<Self> {
        let name = WorkloadName::from_service_name(&service.name)?;
        let definition = match toml::from_str::<Service>(&service.definition) {
            Ok(definition) => definition,
            Err(error) => {
                tracing::warn!(service = %service.name, %error, "ignoring an unparsable workload");
                return None;
            }
        };
        let Some(workload) = service_file::to_workload(&definition) else {
            tracing::warn!(service = %service.name, "ignoring a service without its workload");
            return None;
        };
        // The API never shadows user-data, which owns the name if both had it.
        let source = if has_layer(service, Layer::Runtime) {
            Source::UserData
        } else if has_layer(service, Layer::Persistent) {
            Source::Api
        } else {
            tracing::warn!(service = %service.name, "ignoring a workload service of the image");
            return None;
        };
        Some(Self {
            name,
            workload,
            source,
        })
    }

    /// The workloads among `services`, by name, with their services.
    #[must_use]
    pub fn from_services(services: Vec<api::Service>) -> Vec<(Self, api::Service)> {
        let mut workloads: Vec<_> = services
            .into_iter()
            .filter_map(|service| Some((Self::from_service(&service)?, service)))
            .collect();
        workloads.sort_by(|(a, _), (b, _)| a.name.cmp(&b.name));
        workloads
    }
}

/// Whether `service` has a file in `layer`.
#[must_use]
pub fn has_layer(service: &api::Service, layer: Layer) -> bool {
    service.layers.contains(&i32::from(api::Layer::from(layer)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service_file::tests::workload;

    fn service(name: &str, layers: &[Layer]) -> api::Service {
        let name: WorkloadName = name.parse().unwrap();
        api::Service {
            name: name.service_name().to_string(),
            layers: layers
                .iter()
                .map(|layer| i32::from(api::Layer::from(*layer)))
                .collect(),
            definition: service_file::to_toml(&name, &workload()).unwrap(),
            ..api::Service::default()
        }
    }

    #[test]
    fn workloads_of_both_layers() {
        let services = vec![
            service("web", &[Layer::Runtime]),
            service("db", &[Layer::Persistent]),
            // Both: user-data's.
            service("both", &[Layer::Runtime, Layer::Persistent]),
            // Not workloads, or broken ones: not listed.
            api::Service {
                name: "kubelet".into(),
                layers: [Layer::Image, Layer::Runtime]
                    .map(|layer| i32::from(api::Layer::from(layer)))
                    .to_vec(),
                definition: "exec = [\"/usr/bin/kubelet\"]\n".into(),
                ..api::Service::default()
            },
            api::Service {
                definition: "exec = 1\n".into(),
                ..service("broken", &[Layer::Persistent])
            },
            api::Service {
                definition: "exec = [\"/bin/true\"]\n".into(),
                ..service("bare", &[Layer::Persistent])
            },
            service("image", &[Layer::Image]),
        ];
        let listed: Vec<(String, Source)> = DefinedWorkload::from_services(services)
            .into_iter()
            .map(|(defined, _)| (defined.name.to_string(), defined.source))
            .collect();
        assert_eq!(
            listed,
            [
                ("both".to_owned(), Source::UserData),
                ("db".to_owned(), Source::Api),
                ("web".to_owned(), Source::UserData),
            ]
        );
    }
}

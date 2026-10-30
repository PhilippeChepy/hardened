//! What serviced's API shows of the services: the supervisor updates it after each change, the API
//! reads it.

use std::collections::BTreeMap;
use std::sync::Arc;

use libserviced::definition::{Access, Layer, Service, ServiceName};
use tokio::sync::RwLock;

use crate::service_status::ServiceStatus;

/// A service, as the API shows it.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceView {
    /// As it runs: merged from its files.
    pub definition: Arc<Service>,
    /// The layers it has a file in, in order; none once removed (while it stops).
    pub layers: Vec<Layer>,
    pub status: ServiceStatus,
}

/// The services, as last updated.
#[derive(Default)]
pub struct Overview {
    services: RwLock<BTreeMap<ServiceName, ServiceView>>,
}

impl Overview {
    /// The services are now `services`.
    pub async fn set_services(&self, services: BTreeMap<ServiceName, ServiceView>) {
        *self.services.write().await = services;
    }

    /// The services.
    #[must_use]
    pub async fn services(&self) -> BTreeMap<ServiceName, ServiceView> {
        self.services.read().await.clone()
    }

    /// Service `name`, if known.
    #[must_use]
    pub async fn service(&self, name: &ServiceName) -> Option<ServiceView> {
        self.services.read().await.get(name).cloned()
    }

    /// Whether service `name` exists and its `api` grants `access` (`None`: whatever it grants).
    #[must_use]
    pub async fn grants(&self, name: &ServiceName, access: Option<Access>) -> bool {
        self.services.read().await.get(name).is_some_and(|service| {
            access.is_none_or(|access| service.definition.api.contains(&access))
        })
    }
}

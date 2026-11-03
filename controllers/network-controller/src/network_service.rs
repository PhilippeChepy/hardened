//! `hardened.network.v1.NetworkController`: the DNS override, what DHCP offered, and the
//! interfaces' configurations.
//!
//! The socket's allow-list names the services that may call; the methods changing the network
//! are, in addition, root's: a service whose processes run as several users (a login service's
//! sessions, in its cgroup) may only have its root processes change it, as serviced's `api-users`
//! does for its API.

use std::pin::Pin;
use std::sync::Arc;

use libserviced::authorization::Caller;
use network_controller::DnsSettings;
use network_controller::InterfaceName;
use network_controller::InterfaceSettings;
use network_controller::network;
use network_controller::network::network_controller_server::NetworkController;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;

use crate::command::Commands;
use crate::shared::Shared;

/// Serves the state of [`Shared`], and applies the DNS override to it; asks the interfaces'
/// task about the interfaces through `commands`.
pub struct NetworkService {
    shared: Arc<Shared>,
    commands: Commands,
}

impl NetworkService {
    /// Serves `shared`, and the interfaces through `commands`.
    #[must_use]
    pub fn new(shared: Arc<Shared>, commands: Commands) -> Self {
        Self { shared, commands }
    }
}

/// Fails with PERMISSION_DENIED unless `request` comes from a root process (see the module's
/// documentation). A request without a caller (not served through serviced's authorization:
/// tests) is let through.
fn require_root<T>(request: &Request<T>) -> Result<(), Status> {
    match Caller::of(request) {
        Some(caller) if caller.uid() != 0 => Err(Status::permission_denied(format!(
            "only root's processes of {} may change the network",
            caller.service()
        ))),
        Some(_) | None => Ok(()),
    }
}

/// The interface `name` of a request.
fn interface_name(name: String) -> Result<InterfaceName, Status> {
    InterfaceName::try_from(name)
        .map_err(|error| Status::invalid_argument(format!("name: {error}")))
}

/// The states `WatchState` sends.
type States = Pin<Box<dyn Stream<Item = Result<network::State, Status>> + Send>>;

#[tonic::async_trait]
impl NetworkController for NetworkService {
    type WatchStateStream = States;

    async fn configure(
        &self,
        request: Request<network::Configuration>,
    ) -> Result<Response<()>, Status> {
        require_root(&request)?;
        let dns = DnsSettings::try_from(request.into_inner())
            .map_err(|error| Status::invalid_argument(error.to_string()))?;
        if let Err(error) = self.shared.configure_dns(dns) {
            tracing::error!(error = format!("{error:#}"), "persisting the DNS override");
            return Err(Status::internal(format!("{error:#}")));
        }
        Ok(Response::new(()))
    }

    async fn get_state(&self, _: Request<()>) -> Result<Response<network::State>, Status> {
        Ok(Response::new(self.shared.offered.borrow().clone()))
    }

    async fn watch_state(&self, _: Request<()>) -> Result<Response<States>, Status> {
        let mut offered = self.shared.offered.subscribe();
        let (sender, receiver) = mpsc::channel(1);
        tokio::spawn(async move {
            loop {
                let state = offered.borrow_and_update().clone();
                if sender.send(Ok(state)).await.is_err() {
                    return;
                }
                tokio::select! {
                    changed = offered.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    () = sender.closed() => return,
                }
            }
        });
        Ok(Response::new(Box::pin(ReceiverStream::new(receiver))))
    }

    async fn list_interfaces(
        &self,
        _: Request<()>,
    ) -> Result<Response<network::InterfaceList>, Status> {
        let interfaces = self.commands.list().await?;
        Ok(Response::new(network::InterfaceList { interfaces }))
    }

    async fn set_interface_config(
        &self,
        request: Request<network::SetInterfaceConfigRequest>,
    ) -> Result<Response<network::Interface>, Status> {
        require_root(&request)?;
        let request = request.into_inner();
        let name = interface_name(request.name)?;
        let settings = InterfaceSettings::try_from(request.config.unwrap_or_default())
            .map_err(|error| Status::invalid_argument(format!("config.{error}")))?;
        let interface = self.commands.configure(name, Some(settings)).await?;
        Ok(Response::new(interface))
    }

    async fn reset_interface_config(
        &self,
        request: Request<network::InterfaceRef>,
    ) -> Result<Response<network::Interface>, Status> {
        require_root(&request)?;
        let name = interface_name(request.into_inner().name)?;
        let interface = self.commands.configure(name, None).await?;
        Ok(Response::new(interface))
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use network_controller::network::interface_config::Ipv4;
    use tokio_stream::StreamExt as _;

    use super::*;
    use crate::command::Command;
    use crate::persisted_state;
    use crate::shared::tests::lease;
    use crate::shared::tests::shared;

    fn service(dir: &Path) -> NetworkService {
        service_with(dir).0
    }

    /// The service, and the requests its interfaces' task would get (none is answered).
    fn service_with(dir: &Path) -> (NetworkService, mpsc::Receiver<Command>) {
        let shared = Arc::new(shared(dir));
        shared.bind(
            0,
            2,
            "eth0",
            lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]),
        );
        let (sender, commands) = mpsc::channel(4);
        (NetworkService::new(shared, Commands::new(sender)), commands)
    }

    /// `message`, as a root process of `service` or another user's sends it.
    fn from<T>(uid: u32, message: T) -> Request<T> {
        let mut request = Request::new(message);
        request
            .extensions_mut()
            .insert(Caller::new("login-manager".parse().unwrap(), 42, uid));
        request
    }

    /// Answers the next command as the interfaces' task would: lists `eth0`, configures it.
    async fn answer(commands: &mut mpsc::Receiver<Command>) -> Option<InterfaceSettings> {
        match commands.recv().await.unwrap() {
            Command::List(reply) => {
                let eth0 = network::Interface {
                    name: "eth0".to_owned(),
                    ..network::Interface::default()
                };
                reply.send(vec![eth0]).unwrap();
                None
            }
            Command::Configure {
                name,
                settings,
                reply,
            } => {
                let interface = network::Interface {
                    name: name.to_string(),
                    configured: settings.is_some(),
                    config: settings.clone().map(network::InterfaceConfig::from),
                    ..network::Interface::default()
                };
                reply.send(Ok(interface)).unwrap();
                settings
            }
        }
    }

    fn static_request(name: &str, address: &str) -> network::SetInterfaceConfigRequest {
        network::SetInterfaceConfigRequest {
            name: name.to_owned(),
            config: Some(network::InterfaceConfig {
                ipv4: Some(Ipv4::StaticIpv4(network::StaticIpv4 {
                    addresses: vec![network::Ipv4Address {
                        address: address.to_owned(),
                        prefix_length: 24,
                    }],
                    gateway: Some("192.0.2.1".to_owned()),
                })),
                ..network::InterfaceConfig::default()
            }),
        }
    }

    async fn configure(
        service: &NetworkService,
        name_servers: &[&str],
        search_list: &[&str],
    ) -> Result<(), Status> {
        let configuration = network::Configuration {
            name_servers: name_servers.iter().map(|&s| s.to_owned()).collect(),
            search_list: search_list.iter().map(|&s| s.to_owned()).collect(),
        };
        service
            .configure(Request::new(configuration))
            .await
            .map(Response::into_inner)
    }

    fn resolv_conf(dir: &Path) -> String {
        fs::read_to_string(dir.join("resolv.conf")).unwrap()
    }

    #[tokio::test]
    async fn applies_and_persists_the_override() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let leased = "# Generated by network-controller.\nnameserver 10.0.0.2\nsearch a.internal\n";
        assert_eq!(resolv_conf(dir.path()), leased);

        configure(&service, &["192.0.2.53"], &["corp.example"])
            .await
            .unwrap();
        assert_eq!(
            resolv_conf(dir.path()),
            "# Generated by network-controller.\nnameserver 192.0.2.53\nsearch corp.example\n"
        );
        let persisted = persisted_state::load(&dir.path().join("state.json")).unwrap();
        assert_eq!(
            persisted.name_servers,
            ["192.0.2.53".parse::<std::net::IpAddr>().unwrap()]
        );

        configure(&service, &[], &[]).await.unwrap();
        assert_eq!(resolv_conf(dir.path()), leased, "back to DHCP");
    }

    #[tokio::test]
    async fn watching_sends_the_state_then_its_changes() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        let mut states = service
            .watch_state(Request::new(()))
            .await
            .unwrap()
            .into_inner();
        let next = async |states: &mut States| states.next().await.unwrap().unwrap();
        assert_eq!(next(&mut states).await.ntp_servers, ["10.0.0.4"]);

        let mut lease = lease(&[[10, 0, 0, 2]], Some("a.internal"), &[]);
        lease.ntp_servers = vec![[10, 0, 0, 6].into()];
        service.shared.bind(0, 2, "eth0", lease.clone());
        assert_eq!(next(&mut states).await.ntp_servers, ["10.0.0.6"]);
        // The same lease again is no change: what follows is the release.
        service.shared.bind(0, 2, "eth0", lease);
        service.shared.unbind(0);
        assert_eq!(next(&mut states).await, network::State::default());
    }

    #[tokio::test]
    async fn refuses_an_invalid_override() {
        let dir = tempfile::tempdir().unwrap();
        let service = service(dir.path());
        configure(&service, &["192.0.2.53"], &[]).await.unwrap();
        let configured = resolv_conf(dir.path());
        for (name_servers, search_list) in [
            (&["ns1.example"][..], &[][..]),
            (&[][..], &["a\nnameserver 192.0.2.1"][..]),
        ] {
            let status = configure(&service, name_servers, search_list)
                .await
                .unwrap_err();
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status:?}");
        }
        assert_eq!(resolv_conf(dir.path()), configured, "unchanged");
    }

    #[tokio::test]
    async fn forwards_the_interfaces_to_their_task() {
        let dir = tempfile::tempdir().unwrap();
        let (service, mut commands) = service_with(dir.path());

        let (listed, settings) = tokio::join!(
            service.list_interfaces(from(1000, ())),
            answer(&mut commands)
        );
        assert_eq!(listed.unwrap().into_inner().interfaces[0].name, "eth0");
        assert_eq!(settings, None);

        let request = from(0, static_request("eth0", "192.0.2.10"));
        let (configured, settings) =
            tokio::join!(service.set_interface_config(request), answer(&mut commands));
        let interface = configured.unwrap().into_inner();
        assert!(interface.configured);
        let settings = settings.unwrap();
        assert_eq!(
            settings
                .static_ipv4()
                .unwrap()
                .addresses()
                .first()
                .to_string(),
            "192.0.2.10/24"
        );

        let request = from(
            0,
            network::InterfaceRef {
                name: "eth0".to_owned(),
            },
        );
        let (reset, settings) = tokio::join!(
            service.reset_interface_config(request),
            answer(&mut commands)
        );
        assert!(!reset.unwrap().into_inner().configured);
        assert_eq!(settings, None, "back to the default");
    }

    #[tokio::test]
    async fn changes_are_root_s() {
        let dir = tempfile::tempdir().unwrap();
        let (service, mut commands) = service_with(dir.path());
        let leased = resolv_conf(dir.path());
        let denied = |result: Result<_, Status>| {
            let status = result.unwrap_err();
            assert_eq!(status.code(), tonic::Code::PermissionDenied, "{status:?}");
            assert!(status.message().contains("login-manager"), "{status:?}");
        };
        let dns = network::Configuration {
            name_servers: vec!["192.0.2.53".to_owned()],
            search_list: Vec::new(),
        };
        denied(service.configure(from(1000, dns.clone())).await.map(drop));
        assert_eq!(resolv_conf(dir.path()), leased);
        denied(
            service
                .set_interface_config(from(1000, static_request("eth0", "192.0.2.10")))
                .await
                .map(drop),
        );
        let reset = network::InterfaceRef {
            name: "eth0".to_owned(),
        };
        denied(
            service
                .reset_interface_config(from(1000, reset))
                .await
                .map(drop),
        );
        assert!(
            commands.try_recv().is_err(),
            "nothing reached the interfaces"
        );

        service.configure(from(0, dns)).await.unwrap();
        assert_ne!(resolv_conf(dir.path()), leased);
    }

    #[tokio::test]
    async fn refuses_invalid_configurations() {
        let dir = tempfile::tempdir().unwrap();
        let (service, mut commands) = service_with(dir.path());
        for (request, expected) in [
            (static_request("eth/0", "192.0.2.10"), "name: "),
            (
                static_request("eth0", "192.0.2.0"),
                "config.static_ipv4.addresses[0]: ",
            ),
            (
                static_request("eth0", "10.0.0.10"),
                "config.static_ipv4: gateway 192.0.2.1",
            ),
        ] {
            let status = service
                .set_interface_config(from(0, request))
                .await
                .unwrap_err();
            assert_eq!(status.code(), tonic::Code::InvalidArgument, "{status:?}");
            assert!(status.message().starts_with(expected), "{status:?}");
        }
        assert!(
            commands.try_recv().is_err(),
            "nothing reached the interfaces"
        );
    }

    #[tokio::test]
    async fn the_interfaces_task_gone_is_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let (service, commands) = service_with(dir.path());
        drop(commands);
        let status = service.list_interfaces(from(0, ())).await.unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
    }
}

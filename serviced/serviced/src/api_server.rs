//! Serving serviced's API on its socket, [`libserviced::SOCKET`]: anyone who sees it may connect
//! (mode 0666), each call is checked ([`ServicedService`]).

use std::path::Path;

use anyhow::Context as _;
use libserviced::api::serviced_server::ServicedServer;
use libserviced::authorization::CallerStream;
use tokio::net::UnixListener;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::UnixListenerStream;
use tracing::error;

use crate::caller::Caller;
use crate::service_sockets;
use crate::serviced_service::ServicedService;

/// Binds serviced's socket at `socket`, replacing a stale one.
pub fn bind(socket: &Path) -> anyhow::Result<UnixListener> {
    let listener = service_sockets::listen(socket)
        .with_context(|| format!("listening on {}", socket.display()))?;
    listener.set_nonblocking(true)?;
    Ok(UnixListener::from_std(listener)?)
}

/// Serves `service` on `listener`, its callers found by its resolver, as long as serviced runs.
pub async fn serve(listener: UnixListener, service: ServicedService) {
    let resolve = service.resolve.clone();
    let incoming = UnixListenerStream::new(listener).map(move |stream| {
        stream.map(|stream| {
            let caller = Caller::of(&stream, &resolve);
            CallerStream::new(stream, caller)
        })
    });
    let served = tonic::transport::Server::builder()
        .add_service(ServicedServer::new(service))
        .serve_with_incoming(incoming)
        .await;
    if let Err(e) = served {
        error!(error = %e, "serviced's API stopped");
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use libserviced::api;
    use libserviced::api::serviced_client::ServicedClient;
    use libserviced::definition::{Layer, ServiceName};
    use tokio::sync::mpsc;
    use tonic::Code;
    use tonic::transport::Channel;

    use super::*;
    use crate::caller::Resolver;
    use crate::command::Command;
    use crate::engine::Refusal;
    use crate::log_buffer::LogBuffer;
    use crate::log_store::LogStore;
    use crate::overview::{Overview, ServiceView};
    use crate::service_status::{ServiceStatus, State};
    use crate::shutdown_locks::ShutdownLocks;

    /// The pid `IdentifyProcess` knows as kubelet's.
    const KUBELET_PID: u32 = 4242;

    /// serviced's API on a socket of its own, its caller's service chosen by the test.
    struct Api {
        /// Holds the socket.
        _dir: tempfile::TempDir,
        socket: PathBuf,
        /// The service of the next connection.
        caller: Arc<Mutex<Option<ServiceName>>>,
        serviced_log: Arc<LogBuffer>,
        reloads: mpsc::UnboundedReceiver<()>,
        shutdown_locks: Arc<ShutdownLocks>,
    }

    impl Api {
        async fn start() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let socket = dir.path().join("serviced.sock");
            let overview = Arc::new(Overview::default());
            let service = |api: &str| ServiceView {
                definition: Arc::new(
                    toml::from_str(&format!("exec = [\"/usr/bin/x\"]\napi = {api}\n")).unwrap(),
                ),
                layers: vec![Layer::Image],
                status: ServiceStatus::new(State::Ready),
            };
            overview
                .set_services(BTreeMap::from([
                    (
                        name("machine-controller"),
                        service(r#"["read", "control"]"#),
                    ),
                    (name("time-controller"), service(r#"["read"]"#)),
                    (name("web"), service("[]")),
                    (
                        name("getty"),
                        service(&format!(
                            "[\"read\", \"control\"]\napi-users = [{}]",
                            rustix::process::getuid().as_raw()
                        )),
                    ),
                    (
                        name("getty-other"),
                        service(&format!(
                            "[\"read\", \"control\"]\napi-users = [{}]",
                            rustix::process::getuid().as_raw() + 1
                        )),
                    ),
                ]))
                .await;
            let serviced_log = Arc::new(LogBuffer::new(100, 1 << 20));
            let (commands, mut received) = mpsc::unbounded_channel();
            let (power, _) = mpsc::channel(1);
            let caller: Arc<Mutex<Option<ServiceName>>> = Arc::default();
            let shutdown_locks = Arc::new(ShutdownLocks::default());
            let chosen = caller.clone();
            let me = std::process::id();
            let resolve: Resolver = Arc::new(move |pid| match pid {
                KUBELET_PID => Some(name("kubelet")),
                pid if pid == me => chosen.lock().unwrap().clone(),
                _ => None,
            });
            let service = ServicedService {
                overview,
                logs: Arc::new(LogStore::new(serviced_log.clone())),
                resolve,
                commands,
                power,
                shutdown_locks: shutdown_locks.clone(),
            };
            // The supervisor, as far as the API sees it.
            let (reloaded, reloads) = mpsc::unbounded_channel();
            tokio::spawn(async move {
                while let Some(command) = received.recv().await {
                    match command {
                        Command::Reload(reply) => {
                            let _ = reloaded.send(());
                            let _ = reply.send(vec!["service web: invalid".to_owned()]);
                        }
                        Command::Start(service, reply)
                        | Command::Stop(service, reply)
                        | Command::Restart(service, reply) => {
                            let known = ["machine-controller", "time-controller", "web"]
                                .contains(&service.as_str());
                            let _ = reply.send(if known { Ok(()) } else { Err(Refusal::Unknown) });
                        }
                    }
                }
            });
            tokio::spawn(serve(bind(&socket).unwrap(), service));
            Self {
                _dir: dir,
                socket,
                caller,
                serviced_log,
                reloads,
                shutdown_locks,
            }
        }

        /// A connection as service `service`.
        async fn client(&self, service: Option<&str>) -> ServicedClient<Channel> {
            *self.caller.lock().unwrap() = service.map(name);
            let mut client = libserviced::connect_to(&self.socket).await.unwrap();
            // The connection is made: its caller is known.
            let _ = client.list_services(()).await;
            client
        }
    }

    async fn next<T>(stream: &mut tonic::Streaming<T>) -> T {
        tokio::time::timeout(Duration::from_secs(5), stream.message())
            .await
            .expect("in time")
            .unwrap()
            .expect("a message")
    }

    fn name(name: &str) -> ServiceName {
        name.parse().unwrap()
    }

    fn service_ref(service: &str) -> api::ServiceRef {
        api::ServiceRef {
            name: service.into(),
        }
    }

    #[tokio::test]
    async fn calls_need_the_caller_s_access() {
        let api = Api::start().await;
        let mut ntp = api.client(Some("time-controller")).await;
        let services = ntp.list_services(()).await.unwrap().into_inner().services;
        let names: Vec<&str> = services
            .iter()
            .map(|service| service.name.as_str())
            .collect();
        assert_eq!(
            names,
            [
                "getty",
                "getty-other",
                "machine-controller",
                "time-controller",
                "web"
            ]
        );
        assert_eq!(services[2].state(), api::State::Ready);
        assert_eq!(
            services[2].layers().collect::<Vec<_>>(),
            [api::Layer::Image]
        );
        assert!(services[2].definition.contains("exec = [\"/usr/bin/x\"]"));

        let refused = [
            ntp.restart(service_ref("web")).await.unwrap_err(),
            ntp.reboot(()).await.unwrap_err(),
        ];
        for status in refused {
            assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
        }
        for service in [Some("web"), None] {
            let mut client = api.client(service).await;
            let status = client.get_service(service_ref("web")).await.unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{service:?}");
        }

        let mut controller = api.client(Some("machine-controller")).await;
        controller.restart(service_ref("web")).await.unwrap();
        for status in [
            controller.start(service_ref("missing")).await.unwrap_err(),
            controller
                .get_service(service_ref("missing"))
                .await
                .unwrap_err(),
            controller
                .get_service(service_ref("Not A Service"))
                .await
                .unwrap_err(),
        ] {
            assert_eq!(status.code(), Code::NotFound, "{status:?}");
        }
    }

    #[tokio::test]
    async fn shutdown_locks_last_as_long_as_their_stream() {
        let api = Api::start().await;
        let lock = |delay_seconds| api::ShutdownLock { delay_seconds };
        let mut ntp = api.client(Some("time-controller")).await;
        let status = ntp.watch_shutdown(lock(30)).await.unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied, "needs control");

        let mut controller = api.client(Some("machine-controller")).await;
        let status = controller.watch_shutdown(lock(0)).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);
        let mut events = controller
            .watch_shutdown(lock(30))
            .await
            .unwrap()
            .into_inner();
        assert!(!next(&mut events).await.shutting_down);
        assert_eq!(api.shutdown_locks.announce(), Some(Duration::from_secs(30)));
        assert!(next(&mut events).await.shutting_down);

        drop(events);
        tokio::time::timeout(Duration::from_secs(5), api.shutdown_locks.released())
            .await
            .expect("released once the stream is closed");
    }

    #[tokio::test]
    async fn api_users_limit_a_grant_to_their_processes() {
        let api = Api::start().await;
        let mut mine = api.client(Some("getty")).await;
        mine.restart(service_ref("web")).await.unwrap();
        let mut other = api.client(Some("getty-other")).await;
        for status in [
            other.restart(service_ref("web")).await.unwrap_err(),
            other.list_services(()).await.unwrap_err(),
        ] {
            assert_eq!(status.code(), Code::PermissionDenied, "{status:?}");
        }
        let identified = other
            .identify_process(api::ProcessRef { pid: KUBELET_PID })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(identified.name, "kubelet", "IdentifyProcess needs no grant");
    }

    #[tokio::test]
    async fn every_service_identifies_processes() {
        let api = Api::start().await;
        let identify = |pid| api::ProcessRef { pid };
        let mut web = api.client(Some("web")).await;
        let kubelet = web
            .identify_process(identify(KUBELET_PID))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(kubelet.name, "kubelet", "open to a service without api");
        let me = std::process::id();
        assert_eq!(
            web.identify_process(identify(me))
                .await
                .unwrap()
                .into_inner()
                .name,
            "web"
        );
        for (pid, code) in [(1, Code::NotFound), (0, Code::InvalidArgument)] {
            let status = web.identify_process(identify(pid)).await.unwrap_err();
            assert_eq!(status.code(), code, "{pid}");
        }

        let mut stranger = api.client(None).await;
        let status = stranger
            .identify_process(identify(KUBELET_PID))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied, "not a service");
    }

    #[tokio::test]
    async fn reloads_answer_once_done() {
        let mut api = Api::start().await;
        let mut ntp = api.client(Some("time-controller")).await;
        let status = ntp.reload(()).await.unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied, "control only");
        assert!(api.reloads.try_recv().is_err());

        let mut controller = api.client(Some("machine-controller")).await;
        let response = controller.reload(()).await.unwrap().into_inner();
        api.reloads.try_recv().expect("reloaded before answering");
        assert_eq!(response.invalid, ["service web: invalid"]);
    }

    #[tokio::test]
    async fn logs_tail_then_follow() {
        let api = Api::start().await;
        for text in ["one", "two", "three"] {
            api.serviced_log
                .push("INFO", "serviced", text.to_owned())
                .unwrap();
        }
        let mut ntp = api.client(Some("time-controller")).await;
        let request = |service: &str, tail, follow| api::LogsRequest {
            service: service.into(),
            tail,
            follow,
        };
        let mut lines = ntp.logs(request("", 2, true)).await.unwrap().into_inner();
        let mut texts = Vec::new();
        for _ in 0..2 {
            texts.push(lines.message().await.unwrap().unwrap().text);
        }
        assert_eq!(texts, ["two", "three"]);
        api.serviced_log
            .push("WARN", "serviced::run", "four".to_owned())
            .unwrap();
        let line = next(&mut lines).await;
        assert_eq!(
            (
                line.level.as_str(),
                line.target.as_str(),
                line.text.as_str()
            ),
            ("WARN", "serviced::run", "four")
        );
        assert!(line.time.is_some());

        let mut all = ntp.logs(request("", 0, false)).await.unwrap().into_inner();
        let mut count = 0;
        while all.message().await.unwrap().is_some() {
            count += 1;
        }
        assert_eq!(count, 4, "all of it, then the end");

        let mut web = ntp
            .logs(request("web", 0, false))
            .await
            .unwrap()
            .into_inner();
        assert!(
            web.message().await.unwrap().is_none(),
            "a service that did not run yet"
        );
        let status = ntp.logs(request("missing", 0, false)).await.unwrap_err();
        assert_eq!(status.code(), Code::NotFound);
    }
}

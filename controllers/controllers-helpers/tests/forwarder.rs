//! Forwarding serviced's API to a fake serviced, through a socket of its own.

use std::path::Path;

use controllers_helpers::Forwarder;
use libserviced::api::ServiceRef;
use libserviced::api::serviced_client::ServicedClient;
use libserviced::api::serviced_server::ServicedServer;
use libserviced::definition::Layer;
use libserviced::testing::Call;
use libserviced::testing::FakeServiced;
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::Code;
use tonic::transport::Channel;
use tonic::transport::Server;

/// Serves a forwarder to `upstream` on `dir/front.sock`, and connects to it.
async fn front(dir: &Path, upstream: &Path) -> ServicedClient<Channel> {
    let socket = dir.join("front.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let forwarder = Forwarder::<ServicedServer<()>>::new(upstream, "serviced does not run");
    tokio::spawn(
        Server::builder()
            .add_service(forwarder)
            .serve_with_incoming(UnixListenerStream::new(listener)),
    );
    ServicedClient::new(controllers_helpers::channel(&socket).await.unwrap())
}

#[tokio::test]
async fn relays_calls_and_statuses() {
    let dir = tempfile::tempdir().unwrap();
    let (fake, _) = FakeServiced::start(dir.path(), dir.path()).await;
    let mut client = front(dir.path(), &dir.path().join("serviced.sock")).await;

    fake.put(Layer::Runtime, "web", "enabled = true\n");
    client.reload(()).await.unwrap();
    let services = client.list_services(()).await.unwrap().into_inner();
    assert_eq!(services.services[0].name, "web");
    let error = client
        .start(ServiceRef {
            name: "db".to_owned(),
        })
        .await
        .unwrap_err();
    assert_eq!(error.code(), Code::NotFound, "statuses pass through");
    assert_eq!(error.message(), "db");
    assert_eq!(fake.take_calls(), [Call::Reload]);
}

#[tokio::test]
async fn an_absent_socket_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.sock");
    let mut client = front(dir.path(), &missing).await;
    let error = client.list_services(()).await.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable);
    assert_eq!(error.message(), "serviced does not run");
}

#[tokio::test]
async fn an_unconnectable_socket_is_unavailable() {
    let dir = tempfile::tempdir().unwrap();
    let stale = dir.path().join("stale.sock");
    drop(std::os::unix::net::UnixListener::bind(&stale).unwrap());
    let mut client = front(dir.path(), &stale).await;
    let error = client.list_services(()).await.unwrap_err();
    assert_eq!(error.code(), Code::Unavailable, "{error:?}");
}

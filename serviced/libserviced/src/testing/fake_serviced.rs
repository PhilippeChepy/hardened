use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use tokio_stream::wrappers::UnixListenerStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::transport::Channel;
use tonic::transport::Server;

use crate::api::ListServicesResponse;
use crate::api::LogLine;
use crate::api::LogsRequest;
use crate::api::ProcessRef;
use crate::api::ReloadResponse;
use crate::api::Service;
use crate::api::ServiceRef;
use crate::api::serviced_client::ServicedClient;
use crate::api::serviced_server::Serviced;
use crate::api::serviced_server::ServicedServer;
use crate::definition;
use crate::definition::Layer;
use crate::definition::ServiceName;

/// What the fake was asked to do, by service name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `Reload`.
    Reload,
    /// `Start` of an existing service.
    Start(String),
    /// `Stop` of an existing service.
    Stop(String),
    /// `Restart` of an existing service.
    Restart(String),
}

/// A serviced reading the service files of the layers below a root, as the machine's does below
/// `/`, and recording what it is asked to do. A service exists while it has a file; its
/// definition is its last layer's file, not merged. What the fake does not implement fails with
/// `unimplemented`.
#[derive(Clone)]
pub struct FakeServiced {
    root: PathBuf,
    calls: Arc<Mutex<Vec<Call>>>,
}

impl FakeServiced {
    /// Serves a fake on `dir/serviced.sock`, reading the layers below `root`, whose writable
    /// layers' directories it creates (serviced and storage-controller do on the machine), and
    /// connects to it.
    ///
    /// # Panics
    ///
    /// When the directories cannot be created, the socket cannot be bound or connected to, or
    /// outside a tokio runtime.
    pub async fn start(dir: &Path, root: &Path) -> (Self, ServicedClient<Channel>) {
        for layer in [Layer::Runtime, Layer::Persistent] {
            fs::create_dir_all(layer.dir_in(root)).expect("the layer's directory");
        }
        let fake = Self {
            root: root.to_owned(),
            calls: Arc::default(),
        };
        let path = dir.join("serviced.sock");
        let listener = tokio::net::UnixListener::bind(&path).expect("the fake's socket");
        tokio::spawn(
            Server::builder()
                .add_service(ServicedServer::new(fake.clone()))
                .serve_with_incoming(UnixListenerStream::new(listener)),
        );
        let client = crate::connect_to(&path)
            .await
            .expect("connected to the fake");
        (fake, client)
    }

    /// Writes a file, unchecked, as the image or an earlier run did.
    ///
    /// # Panics
    ///
    /// When the name is invalid or the file cannot be written.
    pub fn put(&self, layer: Layer, name: &str, contents: &str) {
        let path = self.path(layer, name);
        fs::create_dir_all(path.parent().expect("a layer directory")).expect("the layer");
        fs::write(path, contents).expect("the service file");
    }

    /// The file of `name` in `layer`.
    #[must_use]
    pub fn file(&self, layer: Layer, name: &str) -> Option<String> {
        fs::read_to_string(self.path(layer, name)).ok()
    }

    /// The files' names, with their layers, by layer then name.
    #[must_use]
    pub fn names(&self) -> Vec<(Layer, String)> {
        let mut names = Vec::new();
        for layer in Layer::ALL {
            let Ok(entries) = fs::read_dir(layer.dir_in(&self.root)) else {
                continue;
            };
            let mut files: Vec<String> = entries
                .filter_map(|entry| {
                    let name = entry.ok()?.file_name().into_string().ok()?;
                    let stem = name.strip_suffix(".toml")?;
                    (!stem.starts_with('.')).then(|| stem.to_owned())
                })
                .collect();
            files.sort();
            names.extend(files.into_iter().map(|name| (layer, name)));
        }
        names
    }

    /// The calls made since the last time, in order; tests drop them to start afresh.
    pub fn take_calls(&self) -> Vec<Call> {
        std::mem::take(&mut self.calls())
    }

    fn calls(&self) -> MutexGuard<'_, Vec<Call>> {
        self.calls
            .lock()
            .expect("no test panicked holding the fake's calls")
    }

    fn path(&self, layer: Layer, name: &str) -> PathBuf {
        let name: ServiceName = name.parse().expect("a valid service name");
        definition::service_file(&layer.dir_in(&self.root), &name)
    }

    /// The services the files make.
    fn services(&self) -> Vec<Service> {
        let mut services: Vec<Service> = Vec::new();
        let mut names = self.names();
        names.sort_by(|(a_layer, a), (b_layer, b)| (a, a_layer).cmp(&(b, b_layer)));
        for (layer, name) in names {
            let contents = self.file(layer, &name).unwrap_or_default();
            if services.last().is_none_or(|service| service.name != name) {
                services.push(Service {
                    name: name.clone(),
                    ..Service::default()
                });
            }
            let service = services.last_mut().expect("just pushed");
            service.layers.push(crate::api::Layer::from(layer).into());
            service.definition = contents;
        }
        services
    }

    /// Records `call` on the service `request` names, if it exists.
    fn act(
        &self,
        request: Request<ServiceRef>,
        call: fn(String) -> Call,
    ) -> Result<Response<()>, Status> {
        let name = request.into_inner().name;
        if !self.names().iter().any(|(_, file)| *file == name) {
            return Err(Status::not_found(name));
        }
        self.calls().push(call(name));
        Ok(Response::new(()))
    }
}

#[tonic::async_trait]
impl Serviced for FakeServiced {
    type LogsStream = tokio_stream::Empty<Result<LogLine, Status>>;

    async fn list_services(
        &self,
        _: Request<()>,
    ) -> Result<Response<ListServicesResponse>, Status> {
        let services = self.services();
        Ok(Response::new(ListServicesResponse { services }))
    }

    async fn get_service(&self, _: Request<ServiceRef>) -> Result<Response<Service>, Status> {
        Err(Status::unimplemented("get_service"))
    }

    async fn start(&self, request: Request<ServiceRef>) -> Result<Response<()>, Status> {
        self.act(request, Call::Start)
    }

    async fn stop(&self, request: Request<ServiceRef>) -> Result<Response<()>, Status> {
        self.act(request, Call::Stop)
    }

    async fn restart(&self, request: Request<ServiceRef>) -> Result<Response<()>, Status> {
        self.act(request, Call::Restart)
    }

    async fn reload(&self, _: Request<()>) -> Result<Response<ReloadResponse>, Status> {
        self.calls().push(Call::Reload);
        Ok(Response::new(ReloadResponse::default()))
    }

    async fn logs(&self, _: Request<LogsRequest>) -> Result<Response<Self::LogsStream>, Status> {
        Err(Status::unimplemented("logs"))
    }

    async fn reboot(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("reboot"))
    }

    async fn power_off(&self, _: Request<()>) -> Result<Response<()>, Status> {
        Err(Status::unimplemented("power_off"))
    }

    async fn identify_process(
        &self,
        _: Request<ProcessRef>,
    ) -> Result<Response<ServiceRef>, Status> {
        Err(Status::unimplemented("identify_process"))
    }
}

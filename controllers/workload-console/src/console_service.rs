//! `Console`: each call runs a process in a container.

use std::path::PathBuf;
use std::sync::Arc;

use controllers_helpers::InvalidMessage;
use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::FieldResult as _;
use controllers_helpers::invalid_message::WithinResult as _;
use tokio::sync::Semaphore;
use tokio::sync::mpsc;
use tokio_stream::StreamExt as _;
use tokio_stream::wrappers::ReceiverStream;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use tonic::Streaming;
use workload_console::ContainerId;
use workload_console::ExecProcess;
use workload_console::console::ExecRequest;
use workload_console::console::ExecResponse;
use workload_console::console::ExecStart;
use workload_console::console::console_server::Console;
use workload_console::console::exec_request;

use crate::session::Session;

const MAX_SESSIONS: usize = 16;

pub struct ConsoleService {
    ctr: PathBuf,
    sessions: Arc<Semaphore>,
}

impl ConsoleService {
    #[must_use]
    pub fn new(ctr: PathBuf) -> Self {
        Self {
            ctr,
            sessions: Arc::new(Semaphore::new(MAX_SESSIONS)),
        }
    }
}

#[tonic::async_trait]
impl Console for ConsoleService {
    type ExecStream = ReceiverStream<Result<ExecResponse, Status>>;

    async fn exec(
        &self,
        request: Request<Streaming<ExecRequest>>,
    ) -> Result<Response<Self::ExecStream>, Status> {
        let mut requests = request.into_inner();
        let Some(ExecRequest {
            request: Some(exec_request::Request::Start(start)),
        }) = requests.message().await?
        else {
            return Err(Status::invalid_argument(
                "the first request must be the start",
            ));
        };
        let (container, process) =
            parse_start(start).map_err(|error| Status::invalid_argument(error.to_string()))?;
        let permit = self
            .sessions
            .clone()
            .try_acquire_owned()
            .map_err(|_| Status::resource_exhausted("too many processes running"))?;
        let session = Session::start(&self.ctr, container, process)
            .map_err(|error| Status::internal(format!("running ctr: {error}")))?;
        // A request other than an input ends the call.
        let inputs = requests.map_while(|request| match request {
            Ok(ExecRequest {
                request: Some(exec_request::Request::Input(input)),
            }) => Some(input),
            _ => None,
        });
        let (responses, stream) = mpsc::channel(16);
        tokio::spawn(async move {
            session.relay(inputs, responses).await;
            drop(permit);
        });
        Ok(Response::new(ReceiverStream::new(stream)))
    }
}

fn parse_start(start: ExecStart) -> Result<(ContainerId, ExecProcess), InvalidMessage> {
    let container = ContainerId::try_from(start.container).field("container")?;
    let process = invalid_message::required(start.process, "process")?;
    let process = ExecProcess::try_from(process).within("process")?;
    Ok((container, process))
}

#[cfg(test)]
mod tests {
    use workload_console::console;

    use super::*;

    #[test]
    fn parses_the_start() {
        let start = |container: &str, command: &[&str]| ExecStart {
            container: container.into(),
            process: Some(console::Process {
                command: command.iter().map(|&argument| argument.into()).collect(),
                terminal: None,
            }),
        };
        let (container, process) = parse_start(start("workload-web", &["sh"])).unwrap();
        assert_eq!(container.as_str(), "workload-web");
        assert_eq!(process.command.first().as_str(), "sh");
        let field = |start: ExecStart| parse_start(start).unwrap_err().field().to_owned();
        assert_eq!(field(start("-web", &["sh"])), "container");
        assert_eq!(field(start("web", &[])), "process.command");
        let no_process = ExecStart {
            container: "web".into(),
            process: None,
        };
        assert_eq!(field(no_process), "process");
    }
}

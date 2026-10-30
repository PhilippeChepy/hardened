//! The logs serviced's API serves: serviced's own and each service's output, from memory. The
//! services' output is also in their log files, the record kept across boots: a service's log
//! starts with the last lines of its file, those of the previous boots for the services logging on
//! `/var`.

use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::ErrorKind;
use std::path::Path;
use std::sync::Arc;

use libserviced::definition;
use libserviced::definition::{LogDir, ServiceName};
use tokio::sync::RwLock;

use crate::log_buffer::LogBuffer;

/// The lines kept of a service's output.
const SERVICE_LINES: usize = 2000;
const SERVICE_BYTES: usize = 512 << 10;
/// The lines kept of serviced's log.
pub const SERVICED_LINES: usize = 5000;
pub const SERVICED_BYTES: usize = 1 << 20;
/// How much of the end of a service's log file is read when its log starts.
const FILE_TAIL: u64 = 64 << 10;

/// serviced's log and the services'.
pub struct LogStore {
    serviced: Arc<LogBuffer>,
    services: RwLock<HashMap<ServiceName, Arc<LogBuffer>>>,
}

impl LogStore {
    /// The logs, serviced's being `serviced` (the one its tracing subscriber writes to).
    #[must_use]
    pub fn new(serviced: Arc<LogBuffer>) -> Self {
        Self {
            serviced,
            services: RwLock::default(),
        }
    }

    /// serviced's own log.
    #[must_use]
    pub fn serviced(&self) -> &Arc<LogBuffer> {
        &self.serviced
    }

    /// The log of service `name`, if it has one yet.
    #[must_use]
    pub async fn get(&self, name: &ServiceName) -> Option<Arc<LogBuffer>> {
        self.services.read().await.get(name).cloned()
    }

    /// The log of service `name`; a new one starts with the last lines of its log file (on `/var`
    /// once mounted, else in `/run`).
    #[must_use]
    pub async fn service(&self, name: &ServiceName) -> Arc<LogBuffer> {
        self.services
            .write()
            .await
            .entry(name.clone())
            .or_insert_with(|| {
                let var = definition::log_path(name, LogDir::Var);
                let file = if var.exists() {
                    var
                } else {
                    definition::log_path(name, LogDir::Run)
                };
                let previous = file_tail(&file, FILE_TAIL).unwrap_or_default();
                Arc::new(LogBuffer::with_previous(
                    SERVICE_LINES,
                    SERVICE_BYTES,
                    previous,
                ))
            })
            .clone()
    }
}

/// The complete lines of the last `max` bytes of `path` (none if it does not exist).
fn file_tail(path: &Path, max: u64) -> io::Result<Vec<String>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let start = file.metadata()?.len().saturating_sub(max);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(max).read_to_end(&mut bytes)?;
    let text = String::from_utf8_lossy(&bytes);
    let mut lines: Vec<&str> = text.split('\n').collect();
    // The text after the last newline is a line being written; before the first one, a part.
    lines.pop();
    if start > 0 && !lines.is_empty() {
        lines.remove(0);
    }
    Ok(lines.into_iter().map(str::to_owned).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_complete_lines_of_the_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.log");
        assert!(file_tail(&path, 10).unwrap().is_empty());
        std::fs::write(&path, "first\nsecond\nthird\npartial").unwrap();
        assert_eq!(file_tail(&path, 100).unwrap(), ["first", "second", "third"]);
        assert_eq!(
            file_tail(&path, 16).unwrap(),
            ["third"],
            "the cut line and the line being written are left out"
        );
    }
}

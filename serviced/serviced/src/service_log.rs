//! Services' output: each line goes to the service's log file (rotated as it grows), to its log in
//! memory (serviced's API), to the console for `console` services, and to the tail kept for crash
//! reports.

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Arc;

use libserviced::definition::ServiceName;
use tokio::io::AsyncRead;
use tokio::sync::{Mutex, OwnedMutexGuard};
use tracing::warn;

use crate::log_buffer::LogBuffer;
use crate::log_file::{LogFile, LogFileError};
use crate::logging;

/// Past this size, a service's log moves to `<service>.log.1` and a new one starts.
const MAX_LOG_SIZE: u64 = 32 << 20;
/// Lines of a failed run copied to serviced's log.
const TAIL_LINES: usize = 20;
/// A longer line is cut in pieces (output without newlines must not grow without bound).
const MAX_LINE: usize = 16 << 10;

/// The log of one run of a service, shared by its processes.
pub struct ServiceLog {
    service: ServiceName,
    console: bool,
    memory: Arc<LogBuffer>,
    /// Held from a batch's start to the end of its write: its lines reach memory, the tail and
    /// the file in the order of the file.
    file: Arc<Mutex<LogFile>>,
    tail: Mutex<VecDeque<String>>,
}

impl ServiceLog {
    /// Appends to `path` ([`libserviced::definition::log_path`], chosen when the run starts) and to
    /// `memory`. A `console` service's lines go to the console too.
    pub async fn open(
        service: ServiceName,
        path: PathBuf,
        memory: Arc<LogBuffer>,
        console: bool,
    ) -> Arc<Self> {
        Self::open_sized(service, path, memory, console, MAX_LOG_SIZE).await
    }

    /// [`ServiceLog::open`], rotating past `max_size`.
    async fn open_sized(
        service: ServiceName,
        path: PathBuf,
        memory: Arc<LogBuffer>,
        console: bool,
        max_size: u64,
    ) -> Arc<Self> {
        let log = Arc::new(Self {
            service,
            console,
            memory,
            file: Arc::new(Mutex::new(LogFile::new(path, max_size))),
            tail: Mutex::new(VecDeque::with_capacity(TAIL_LINES)),
        });
        let file = log.file.clone().lock_owned().await;
        log.file_io(file, |file| {
            file.open()
                .err()
                .map(LogFileError::Open)
                .into_iter()
                .collect()
        })
        .await;
        log
    }

    /// Writes `lines`, also to the console for a `console` service unless `quiet`.
    pub async fn write(&self, lines: Vec<String>, quiet: bool) {
        if lines.is_empty() {
            return;
        }
        if self.console && !quiet {
            for line in &lines {
                logging::console(&format!("[{}] {line}", self.service));
            }
        }
        let file = self.file.clone().lock_owned().await;
        {
            let mut tail = self.tail.lock().await;
            for line in &lines {
                if let Err(e) = self.memory.output(line.clone()) {
                    warn!(service = %self.service, error = %e, "cannot keep the output in memory");
                }
                if tail.len() == TAIL_LINES {
                    tail.pop_front();
                }
                tail.push_back(line.clone());
            }
        }
        self.file_io(file, move |file| file.append(&lines)).await;
    }

    /// Runs `io` on `file` on the blocking pool (under writeback pressure, a write to `/var` can
    /// block for long), logging its failures.
    async fn file_io(
        &self,
        mut file: OwnedMutexGuard<LogFile>,
        io: impl FnOnce(&mut LogFile) -> Vec<LogFileError> + Send + 'static,
    ) {
        let path = file.path().to_owned();
        match tokio::task::spawn_blocking(move || io(&mut file)).await {
            Ok(errors) => {
                for e in errors {
                    warn!(
                        service = %self.service,
                        path = %path.display(),
                        error = %e,
                        "writing the log"
                    );
                }
            }
            Err(e) => {
                warn!(service = %self.service, path = %path.display(), error = %e, "log write")
            }
        }
    }

    /// The last lines written.
    #[must_use]
    pub async fn tail(&self) -> Vec<String> {
        self.tail.lock().await.iter().cloned().collect()
    }
}

/// Copies the lines of `output` (a process's stdout and stderr) to `log`, those of each read in
/// one write, until every writer closed it; `quiet` keeps them off the console.
pub async fn pump(mut output: impl AsyncRead + Unpin, log: Arc<ServiceLog>, quiet: bool) {
    use tokio::io::AsyncReadExt as _;

    let mut pending = Vec::new();
    let mut chunk = vec![0u8; 8192];
    loop {
        let read = match output.read(&mut chunk).await {
            Ok(0) | Err(_) => break,
            Ok(read) => read,
        };
        pending.extend_from_slice(&chunk[..read]);
        let mut lines = Vec::new();
        let mut start = 0;
        while let Some(end) = pending[start..].iter().position(|&b| b == b'\n') {
            lines.push(text(&pending[start..start + end]));
            start += end + 1;
        }
        pending.drain(..start);
        while pending.len() >= MAX_LINE {
            lines.push(text(&pending[..MAX_LINE]));
            pending.drain(..MAX_LINE);
        }
        log.write(lines, quiet).await;
    }
    if !pending.is_empty() {
        log.write(vec![text(&pending)], quiet).await;
    }
}

/// `bytes` as text, invalid UTF-8 replaced.
#[must_use]
fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn service() -> ServiceName {
        "web".parse().unwrap()
    }

    #[tokio::test]
    async fn splits_lines_and_keeps_the_tail() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.log");
        std::fs::write(&path, "before\n").unwrap();
        let memory = Arc::new(LogBuffer::new(100, 1 << 20));
        let log = ServiceLog::open(
            service(),
            path.clone(),
            memory.clone(),
            /* console */ false,
        )
        .await;
        let mut output = String::new();
        for i in 0..30 {
            output.push_str(&format!("line {i}\n"));
        }
        output.push_str("no newline");
        pump(output.as_bytes(), log.clone(), /* quiet */ false).await;

        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("before\nline 0\n"), "appended: {text:?}");
        assert!(
            text.ends_with("line 29\nno newline\n"),
            "the last line is kept: {text:?}"
        );
        let tail = log.tail().await;
        assert_eq!(tail.len(), TAIL_LINES);
        assert_eq!(tail[0], "line 11");
        assert_eq!(tail[TAIL_LINES - 1], "no newline");
        let memory = memory.tail(0).unwrap();
        assert_eq!(memory.len(), 31, "and in memory");
        assert_eq!(memory[30].text, "no newline");
    }

    #[tokio::test]
    async fn cuts_long_lines() {
        let dir = tempfile::tempdir().unwrap();
        let memory = Arc::new(LogBuffer::new(100, 1 << 20));
        let log = ServiceLog::open(
            service(),
            dir.path().join("web.log"),
            memory,
            /* console */ false,
        )
        .await;
        let output = vec![b'x'; MAX_LINE * 2 + 3];
        pump(output.as_slice(), log.clone(), /* quiet */ false).await;
        let lengths: Vec<usize> = log.tail().await.iter().map(String::len).collect();
        assert_eq!(lengths, [MAX_LINE, MAX_LINE, 3]);
    }

    #[tokio::test]
    async fn batches_rotate_in_order() {
        use tokio::io::AsyncReadExt as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.log");
        let memory = Arc::new(LogBuffer::new(100, 1 << 20));
        let log = ServiceLog::open_sized(
            service(),
            path.clone(),
            memory,
            /* console */ false,
            /* max_size */ 40,
        )
        .await;
        let lines: Vec<String> = (0..15).map(|i| format!("line {i:02}\n")).collect();
        // Three reads, so three batches; one cuts a line in two.
        let (first, rest) = lines.split_at(4);
        let first = first.concat();
        let rest = rest.concat();
        let (second, third) = rest.split_at(13);
        let output = first
            .as_bytes()
            .chain(second.as_bytes())
            .chain(third.as_bytes());
        pump(output, log.clone(), /* quiet */ false).await;

        let rotated = std::fs::read_to_string(dir.path().join("web.log.1")).unwrap();
        let current = std::fs::read_to_string(&path).unwrap();
        assert!(current.len() <= 40 && rotated.len() <= 40);
        let all = lines.concat();
        assert!(
            all.ends_with(&format!("{rotated}{current}")),
            "in order: {rotated:?} {current:?}"
        );
        assert!(current.ends_with("line 14\n"));
        assert_eq!(log.tail().await.last().unwrap(), "line 14");
    }
}

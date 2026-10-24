//! Container logs, written by the CRI runtime in the kubelet format:
//! `<RFC 3339 time> <stdout|stderr> <P|F> <message>`, one entry per line. `P` entries are
//! partial lines (split by the runtime, or an unterminated last write) continued by the next
//! entry of the same stream; `F` entries end a line.

use std::io::SeekFrom;
use std::path::{Path, PathBuf};

use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

/// Logs larger than this are rotated (once, to `<name>.log.1`) before the workload starts.
const MAX_LOG_SIZE: u64 = 32 << 20;
/// Longest line copied to the console; longer ones are split.
const MAX_LINE: usize = 16 << 10;
/// Longest log entry kept while waiting for its end. The runtime splits lines at 16 KiB, so
/// only a corrupted log reaches it.
const MAX_ENTRY: usize = 64 << 10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogStream {
    Stdout,
    Stderr,
}

/// One log entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry<'a> {
    pub stream: LogStream,
    /// Continued by the next entry of the same stream.
    pub partial: bool,
    pub message: &'a [u8],
}

/// Parses one log line (without its newline). `None` if it is not in the CRI format.
pub fn parse_entry(line: &[u8]) -> Option<Entry<'_>> {
    let mut fields = line.splitn(4, |&b| b == b' ');
    let time = fields.next()?;
    // RFC 3339 times start with the date: a cheap check that this is a CRI entry.
    if time.len() < 20 || !time[..4].iter().all(u8::is_ascii_digit) || time[4] != b'-' {
        return None;
    }
    let stream = match fields.next()? {
        b"stdout" => LogStream::Stdout,
        b"stderr" => LogStream::Stderr,
        _ => return None,
    };
    // Tags are `:`-separated; only `P` (partial) and `F` (full) are defined.
    let tags = fields.next()?;
    let partial = tags.split(|&b| b == b':').any(|tag| tag == b"P");
    if !partial && !tags.split(|&b| b == b':').any(|tag| tag == b"F") {
        return None;
    }
    Some(Entry {
        stream,
        partial,
        message: fields.next().unwrap_or_default(),
    })
}

/// Splits raw log data into entries across reads.
#[derive(Debug, Default)]
struct Splitter {
    pending: Vec<u8>,
    /// Discards data up to the first newline: reading started in the middle of an entry.
    resync: bool,
}

impl Splitter {
    /// Appends `data` and calls `f` with each complete line, without its newline.
    fn push(&mut self, data: &[u8], mut f: impl FnMut(&[u8])) {
        let mut data = data;
        if self.resync {
            match data.iter().position(|&b| b == b'\n') {
                Some(end) => {
                    self.resync = false;
                    data = &data[end + 1..];
                }
                None => return,
            }
        }
        self.pending.extend_from_slice(data);
        let mut start = 0;
        while let Some(end) = self.pending[start..].iter().position(|&b| b == b'\n') {
            f(&self.pending[start..start + end]);
            start += end + 1;
        }
        self.pending.drain(..start);
        if self.pending.len() > MAX_ENTRY {
            f(&std::mem::take(&mut self.pending));
        }
    }
}

/// Decodes a log into the byte stream the container wrote: messages concatenated, `F` entries
/// followed by a newline. Lines not in the CRI format are passed through.
#[derive(Debug, Default)]
pub struct Decoder {
    splitter: Splitter,
}

impl Decoder {
    /// A decoder for data starting at an arbitrary offset: the first, truncated entry is skipped.
    pub fn mid_entry() -> Self {
        Self {
            splitter: Splitter {
                resync: true,
                ..Default::default()
            },
        }
    }

    /// Decodes the complete entries of `data` (and of the data previously given).
    pub fn decode(&mut self, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len());
        self.splitter.push(data, |line| match parse_entry(line) {
            Some(entry) => {
                out.extend_from_slice(entry.message);
                if !entry.partial {
                    out.push(b'\n');
                }
            }
            None => {
                out.extend_from_slice(line);
                out.push(b'\n');
            }
        });
        out
    }
}

/// Reassembles the lines of each stream from the entries of a log.
#[derive(Debug, Default)]
pub struct Lines {
    splitter: Splitter,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

impl Lines {
    /// Returns the lines completed by `data`. Overlong lines are split at [`MAX_LINE`].
    pub fn push(&mut self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut lines = Vec::new();
        let Self {
            splitter,
            stdout,
            stderr,
        } = self;
        splitter.push(data, |line| {
            let Some(entry) = parse_entry(line) else {
                lines.push(line.to_vec());
                return;
            };
            let buffer = match entry.stream {
                LogStream::Stdout => &mut *stdout,
                LogStream::Stderr => &mut *stderr,
            };
            buffer.extend_from_slice(entry.message);
            if !entry.partial {
                lines.push(std::mem::take(buffer));
            }
            while buffer.len() >= MAX_LINE {
                lines.push(buffer.drain(..MAX_LINE).collect());
            }
        });
        lines
    }

    /// The unterminated last lines of each stream.
    pub fn finish(&mut self) -> Vec<Vec<u8>> {
        [&mut self.stdout, &mut self.stderr]
            .into_iter()
            .filter(|buffer| !buffer.is_empty())
            .map(std::mem::take)
            .collect()
    }
}

pub async fn rotate(path: &Path) {
    let Ok(metadata) = tokio::fs::metadata(path).await else {
        return;
    };
    if metadata.len() > MAX_LOG_SIZE {
        let rotated = path.with_extension("log.1");
        if let Err(e) = tokio::fs::rename(path, &rotated).await {
            tracing::warn!("rotating {}: {e}", path.display());
        }
    }
}

/// Copies the lines appended to a workload's log to dust-init's log (and so to the console).
pub struct ConsoleTail {
    name: String,
    path: PathBuf,
    offset: u64,
    lines: Lines,
}

impl ConsoleTail {
    /// Starts at the current end of the log: earlier runs were already shown.
    pub async fn new(name: &str, path: &Path) -> Self {
        let offset = tokio::fs::metadata(path).await.map(|m| m.len()).unwrap_or(0);
        Self {
            name: name.to_owned(),
            path: path.to_owned(),
            offset,
            lines: Lines::default(),
        }
    }

    pub async fn poll(&mut self) {
        let data = match read_from(&self.path, &mut self.offset).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => {
                tracing::debug!("reading {}: {e}", self.path.display());
                return;
            }
        };
        for line in self.lines.push(&data) {
            self.print(&line);
        }
    }

    /// Prints the remaining output, including unterminated last lines.
    pub async fn finish(mut self) {
        self.poll().await;
        for line in self.lines.finish() {
            self.print(&line);
        }
    }

    fn print(&self, line: &[u8]) {
        let line = String::from_utf8_lossy(line);
        tracing::info!("[{}] {}", self.name, line.trim_end_matches('\r'));
    }
}

/// Reads what was appended to `path` since `offset`, restarting from the beginning if the file
/// was truncated or rotated.
async fn read_from(path: &Path, offset: &mut u64) -> std::io::Result<Vec<u8>> {
    let mut file = tokio::fs::File::open(path).await?;
    let len = file.metadata().await?.len();
    if len < *offset {
        *offset = 0;
    }
    file.seek(SeekFrom::Start(*offset)).await?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).await?;
    *offset += data.len() as u64;
    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TIME: &str = "2026-10-25T10:00:00.123456789Z";

    fn entry(stream: &str, tag: &str, message: &str) -> String {
        format!("{TIME} {stream} {tag} {message}\n")
    }

    #[test]
    fn parses_cri_entries() {
        let line = format!("{TIME} stdout F hello from a hardened workload");
        assert_eq!(
            parse_entry(line.as_bytes()),
            Some(Entry {
                stream: LogStream::Stdout,
                partial: false,
                message: b"hello from a hardened workload",
            })
        );
        let line = format!("{TIME} stderr P  two  spaces ");
        let parsed = parse_entry(line.as_bytes()).unwrap();
        assert_eq!(parsed.stream, LogStream::Stderr);
        assert!(parsed.partial);
        assert_eq!(parsed.message, b" two  spaces ");
        // An empty line is written with the trailing separator, or without it.
        assert_eq!(
            parse_entry(format!("{TIME} stdout F ").as_bytes()).unwrap().message,
            b""
        );
        assert_eq!(parse_entry(format!("{TIME} stdout F").as_bytes()).unwrap().message, b"");

        for invalid in [
            "plain output".to_owned(),
            format!("{TIME} stdin F x"),
            format!("{TIME} stdout X x"),
            "2026 stdout F x".to_owned(),
            String::new(),
        ] {
            assert_eq!(parse_entry(invalid.as_bytes()), None, "{invalid:?}");
        }
    }

    #[test]
    fn decodes_the_written_byte_stream() {
        let log = [
            entry("stdout", "P", "hello "),
            entry("stdout", "F", "world"),
            entry("stderr", "F", "oops"),
            entry("stdout", "F", ""),
            entry("stdout", "P", "no newline"),
        ]
        .concat();
        let mut decoder = Decoder::default();
        // Split in the middle of an entry: nothing is emitted before its newline.
        let (first, second) = log.as_bytes().split_at(20);
        assert!(decoder.decode(first).is_empty());
        assert_eq!(decoder.decode(second), b"hello world\noops\n\nno newline");

        let mut decoder = Decoder::default();
        assert_eq!(decoder.decode(b"not cri\n"), b"not cri\n");
    }

    #[test]
    fn skips_the_truncated_first_entry() {
        let log = [entry("stdout", "F", "first"), entry("stdout", "F", "second")].concat();
        let mut decoder = Decoder::mid_entry();
        assert_eq!(decoder.decode(&log.as_bytes()[5..]), b"second\n");
        let mut decoder = Decoder::mid_entry();
        assert!(decoder.decode(b"no newline yet").is_empty());
        assert_eq!(
            decoder.decode(format!("\n{}", entry("stdout", "F", "x")).as_bytes()),
            b"x\n"
        );
    }

    #[test]
    fn reassembles_partial_lines_per_stream() {
        let mut lines = Lines::default();
        let pushed = lines.push(
            [
                entry("stdout", "P", "hello from "),
                entry("stderr", "P", "err "),
                entry("stdout", "F", "a hardened workload"),
                entry("stderr", "F", "line"),
                entry("stdout", "P", "tail"),
            ]
            .concat()
            .as_bytes(),
        );
        assert_eq!(
            pushed,
            [b"hello from a hardened workload".to_vec(), b"err line".to_vec()]
        );
        assert_eq!(lines.finish(), [b"tail".to_vec()]);
        assert!(lines.finish().is_empty());

        let long = "x".repeat(MAX_LINE + 1);
        let pushed = lines.push(entry("stdout", "P", &long).as_bytes());
        assert_eq!(pushed.len(), 1);
        assert_eq!(lines.finish(), [b"x".to_vec()]);
    }

    #[tokio::test]
    async fn console_tail_follows_appends_and_truncation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.log");
        let old = entry("stdout", "F", "old run");
        tokio::fs::write(&path, &old).await.unwrap();

        let mut tail = ConsoleTail::new("x", &path).await;
        assert_eq!(tail.offset, old.len() as u64);

        let mut file = std::fs::OpenOptions::new().append(true).open(&path).unwrap();
        let new = [entry("stdout", "F", "new"), entry("stdout", "P", "part")].concat();
        std::io::Write::write_all(&mut file, new.as_bytes()).unwrap();
        tail.poll().await;
        assert_eq!(tail.offset, (old.len() + new.len()) as u64);
        assert_eq!(tail.lines.stdout, b"part");

        tokio::fs::write(&path, b"ab").await.unwrap();
        let mut offset = 16;
        assert_eq!(read_from(&path, &mut offset).await.unwrap(), b"ab");
        assert_eq!(offset, 2);
    }

    #[tokio::test]
    async fn rotates_large_logs() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.log");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_LOG_SIZE + 1).unwrap();
        rotate(&path).await;
        assert!(!path.exists());
        assert!(dir.path().join("x.log.1").exists());
    }
}

//! The console's writer: a thread of its own, so that the serial console (about 11 KB/s at
//! 115200 baud) never blocks the runtime's workers. The console is best effort: past
//! [`CAPACITY`] waiting lines, lines are dropped and counted; the logs in memory and on file are
//! the record.

use std::io;
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::time::{Duration, Instant};

use crate::logging;

/// Lines waiting for the console, at most.
const CAPACITY: usize = 1024;

/// Queues lines for the console thread.
pub struct ConsoleWriter {
    lines: SyncSender<String>,
    /// Lines dropped since the last report.
    dropped: AtomicU64,
    /// Lines queued and not written yet.
    pending: Arc<AtomicUsize>,
}

impl ConsoleWriter {
    /// Starts the thread writing the queued lines to `sink`.
    pub fn start(sink: impl Write + Send + 'static) -> io::Result<Self> {
        let (writer, lines) = Self::new(CAPACITY);
        let pending = writer.pending.clone();
        std::thread::Builder::new()
            .name("console".to_owned())
            .spawn(move || write_lines(&lines, sink, &pending))?;
        Ok(writer)
    }

    /// A writer queuing up to `capacity` lines, and the queue's receiving end.
    #[must_use]
    fn new(capacity: usize) -> (Self, Receiver<String>) {
        let (lines, receiver) = mpsc::sync_channel(capacity);
        let writer = Self {
            lines,
            dropped: AtomicU64::new(0),
            pending: Arc::default(),
        };
        (writer, receiver)
    }

    /// Queues `line` (newline included), or drops it if the queue is full. Once there is room
    /// again, the count of the lines dropped comes first.
    pub fn send(&self, line: String) {
        let dropped = self.dropped.swap(0, Ordering::Relaxed);
        if dropped > 0 {
            let report =
                logging::console_line(&format!("warning: {dropped} console lines dropped"));
            if !self.try_send(report) {
                self.dropped.fetch_add(dropped + 1, Ordering::Relaxed);
                return;
            }
        }
        if !self.try_send(line) {
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Queues `line` if there is room; returns whether it was.
    #[must_use]
    fn try_send(&self, line: String) -> bool {
        self.pending.fetch_add(1, Ordering::Relaxed);
        let sent = self.lines.try_send(line).is_ok();
        if !sent {
            self.pending.fetch_sub(1, Ordering::Relaxed);
        }
        sent
    }

    /// Waits up to `timeout` for the queued lines to be written: before the machine goes down.
    pub fn flush(&self, timeout: Duration) {
        let deadline = Instant::now() + timeout;
        while self.pending.load(Ordering::Relaxed) > 0 && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
}

/// Writes the lines received to `sink`, until every sender is gone; a failed write is ignored.
fn write_lines(lines: &Receiver<String>, mut sink: impl Write, pending: &AtomicUsize) {
    for line in lines {
        let _ = sink.write_all(line.as_bytes());
        pending.fetch_sub(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_the_dropped_lines() {
        let (writer, lines) = ConsoleWriter::new(2);
        for i in 0..5 {
            writer.send(format!("line {i}\n"));
        }
        let queued: Vec<String> = lines.try_iter().collect();
        assert_eq!(queued, ["line 0\n", "line 1\n"]);

        writer.send("next\n".to_owned());
        let queued: Vec<String> = lines.try_iter().collect();
        assert_eq!(queued.len(), 2);
        assert!(
            queued[0].ends_with("serviced: warning: 3 console lines dropped\n"),
            "{queued:?}"
        );
        assert_eq!(queued[1], "next\n");
    }

    #[test]
    fn a_report_without_room_is_kept_for_later() {
        let (writer, lines) = ConsoleWriter::new(2);
        for line in ["a\n", "b\n", "dropped\n"] {
            writer.send(line.to_owned());
        }
        assert_eq!(lines.recv().unwrap(), "a\n");
        // The report takes the last room: this line is dropped too.
        writer.send("dropped too\n".to_owned());
        assert_eq!(lines.recv().unwrap(), "b\n");
        assert!(
            lines
                .recv()
                .unwrap()
                .ends_with(" 1 console lines dropped\n")
        );
        writer.send("written\n".to_owned());
        let queued: Vec<String> = lines.try_iter().collect();
        assert!(
            queued[0].ends_with(" 1 console lines dropped\n"),
            "{queued:?}"
        );
        assert_eq!(queued[1..], ["written\n"]);
    }

    #[test]
    fn writes_and_flushes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("console");
        let writer = ConsoleWriter::start(std::fs::File::create(&path).unwrap()).unwrap();
        writer.send("one\n".to_owned());
        writer.send("two\n".to_owned());
        writer.flush(Duration::from_secs(5));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "one\ntwo\n");
    }
}

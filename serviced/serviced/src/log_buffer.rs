//! The last lines of a log, kept in memory for serviced's API, and the followers of new ones.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tokio::sync::broadcast;

/// New lines a follower may lag behind before it loses some.
const FOLLOWER_LAG: usize = 1024;

/// A line of a log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    /// When it was written; `None` for lines of a previous boot, read from the log's file.
    pub time: Option<SystemTime>,
    /// For serviced's own log: its level (`INFO`...); empty for services' output.
    pub level: &'static str,
    /// For serviced's own log: the event's target; empty for services' output.
    pub target: &'static str,
    /// Without its newline.
    pub text: String,
}

/// A log whose lock a writer held while panicking: a bug, its lines may be inconsistent. The
/// tracing subscriber writes serviced's log from sync code, so logs cannot use tokio's locks,
/// which are never poisoned.
#[derive(Debug, thiserror::Error)]
#[error("a log in memory is unusable: a writer panicked")]
pub struct Poisoned;

/// The last lines of a log, and the lines written after them.
pub type Following = (Vec<Arc<LogEntry>>, broadcast::Receiver<Arc<LogEntry>>);

/// The last lines of a log, up to a number of lines and of bytes, and its followers.
pub struct LogBuffer {
    max_lines: usize,
    max_bytes: usize,
    inner: Mutex<Inner>,
}

struct Inner {
    lines: VecDeque<Arc<LogEntry>>,
    /// The size of the lines' text.
    bytes: usize,
    followers: broadcast::Sender<Arc<LogEntry>>,
}

impl LogBuffer {
    /// An empty log, keeping up to `max_lines` lines and `max_bytes` of text (the last line is
    /// kept whatever its size).
    #[must_use]
    pub fn new(max_lines: usize, max_bytes: usize) -> Self {
        Self::with_previous(max_lines, max_bytes, Vec::new())
    }

    /// A log starting with `previous`, lines of a previous boot, whose time is unknown.
    #[must_use]
    pub fn with_previous(max_lines: usize, max_bytes: usize, previous: Vec<String>) -> Self {
        let (followers, _) = broadcast::channel(FOLLOWER_LAG);
        let mut inner = Inner {
            lines: VecDeque::new(),
            bytes: 0,
            followers,
        };
        for text in previous {
            let entry = LogEntry {
                time: None,
                level: "",
                target: "",
                text,
            };
            inner.append(max_lines, max_bytes, entry);
        }
        Self {
            max_lines,
            max_bytes,
            inner: Mutex::new(inner),
        }
    }

    /// Appends a line of a service's output, written now.
    ///
    /// # Errors
    ///
    /// When the log is poisoned.
    pub fn output(&self, text: String) -> Result<(), Poisoned> {
        self.push("", "", text)
    }

    /// Appends a line written now, stamped in order: its time is never before the previous
    /// line's, even if the wall clock went back. Must not log: serviced's log is one.
    ///
    /// # Errors
    ///
    /// When the log is poisoned.
    pub fn push(
        &self,
        level: &'static str,
        target: &'static str,
        text: String,
    ) -> Result<(), Poisoned> {
        let mut inner = self.inner.lock().map_err(|_| Poisoned)?;
        let now = SystemTime::now();
        let previous = inner.lines.back().and_then(|line| line.time);
        let time = previous.map_or(now, |previous| previous.max(now));
        let entry = LogEntry {
            time: Some(time),
            level,
            target,
            text,
        };
        inner.append(self.max_lines, self.max_bytes, entry);
        Ok(())
    }

    /// The last `count` lines (all those kept for 0), oldest first.
    ///
    /// # Errors
    ///
    /// When the log is poisoned.
    pub fn tail(&self, count: usize) -> Result<Vec<Arc<LogEntry>>, Poisoned> {
        let inner = self.inner.lock().map_err(|_| Poisoned)?;
        Ok(tail_of(&inner.lines, count))
    }

    /// The last `count` lines (all those kept for 0), and the lines written after them.
    ///
    /// # Errors
    ///
    /// When the log is poisoned.
    pub fn follow(&self, count: usize) -> Result<Following, Poisoned> {
        let inner = self.inner.lock().map_err(|_| Poisoned)?;
        Ok((tail_of(&inner.lines, count), inner.followers.subscribe()))
    }
}

impl Inner {
    /// Appends `entry`, dropping the oldest lines past `max_lines` or `max_bytes`.
    fn append(&mut self, max_lines: usize, max_bytes: usize, entry: LogEntry) {
        let entry = Arc::new(entry);
        self.bytes += entry.text.len();
        self.lines.push_back(entry.clone());
        while self.lines.len() > max_lines || (self.bytes > max_bytes && self.lines.len() > 1) {
            let Some(oldest) = self.lines.pop_front() else {
                break;
            };
            self.bytes -= oldest.text.len();
        }
        // Without followers, there is nobody to send to.
        let _ = self.followers.send(entry);
    }
}

#[must_use]
fn tail_of(lines: &VecDeque<Arc<LogEntry>>, count: usize) -> Vec<Arc<LogEntry>> {
    let skip = match count {
        0 => 0,
        count => lines.len().saturating_sub(count),
    };
    lines.iter().skip(skip).cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(lines: &[Arc<LogEntry>]) -> Vec<&str> {
        lines.iter().map(|line| line.text.as_str()).collect()
    }

    #[test]
    fn keeps_the_last_lines() {
        let log = LogBuffer::new(3, 10);
        for text in ["a", "b", "c", "d"] {
            log.output(text.to_owned()).unwrap();
        }
        assert_eq!(
            texts(&log.tail(0).unwrap()),
            ["b", "c", "d"],
            "3 lines at most"
        );
        assert_eq!(texts(&log.tail(2).unwrap()), ["c", "d"]);
        assert_eq!(texts(&log.tail(9).unwrap()), ["b", "c", "d"]);
        log.output("0123456789".to_owned()).unwrap();
        assert_eq!(
            texts(&log.tail(0).unwrap()),
            ["0123456789"],
            "10 bytes at most"
        );
        log.output("0123456789abc".to_owned()).unwrap();
        assert_eq!(
            texts(&log.tail(0).unwrap()),
            ["0123456789abc"],
            "but the last line"
        );
    }

    #[tokio::test]
    async fn followers_get_the_tail_then_new_lines() {
        let log = LogBuffer::new(10, 1000);
        log.output("old".to_owned()).unwrap();
        log.output("last".to_owned()).unwrap();
        let (tail, mut new) = log.follow(1).unwrap();
        assert_eq!(texts(&tail), ["last"]);
        log.output("new".to_owned()).unwrap();
        assert_eq!(new.recv().await.unwrap().text, "new");
        let times: Vec<SystemTime> = log
            .tail(0)
            .unwrap()
            .iter()
            .filter_map(|line| line.time)
            .collect();
        assert!(times.is_sorted(), "stamped in order");
    }
}

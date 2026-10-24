//! dust-init's log: written to the console and kept in memory for the API (`Machine/Logs`).
//!
//! Console lines look like `[   12.345] dust-init: message key=value`, with a `warning: ` or `error: `
//! prefix for those levels, mirroring kernel messages so the serial console reads as one log.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

/// Number of entries retained in memory.
const CAPACITY: usize = 4096;

#[derive(Debug, Clone)]
pub struct LogRecord {
    pub time: SystemTime,
    pub level: Level,
    pub target: String,
    /// Message followed by its fields as `key=value`.
    pub message: String,
}

/// In-memory log retained for the API, with live subscribers.
#[derive(Clone)]
pub struct LogRing {
    inner: Arc<Mutex<VecDeque<LogRecord>>>,
    live: broadcast::Sender<LogRecord>,
}

impl LogRing {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::with_capacity(CAPACITY))),
            live: broadcast::channel(256).0,
        }
    }

    fn push(&self, record: LogRecord) {
        let mut entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if entries.len() == CAPACITY {
            entries.pop_front();
        }
        entries.push_back(record.clone());
        let _ = self.live.send(record);
    }

    /// The last `tail` entries (all retained entries when 0), oldest first, and a receiver for
    /// the entries logged afterwards. Taken atomically, so following never misses or repeats one.
    pub fn snapshot(&self, tail: usize) -> (Vec<LogRecord>, broadcast::Receiver<LogRecord>) {
        let entries = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let receiver = self.live.subscribe();
        let skip = if tail == 0 {
            0
        } else {
            entries.len().saturating_sub(tail)
        };
        (entries.iter().skip(skip).cloned().collect(), receiver)
    }
}

/// Installs the global subscriber. `RUST_LOG`-style filtering through `dust-init.log=<filter>` on the
/// kernel command line is applied by the caller via `filter`.
pub fn init(filter: &str) -> LogRing {
    let ring = LogRing::new();
    let layer = ConsoleLayer { ring: ring.clone() };
    let filter =
        tracing_subscriber::EnvFilter::try_new(filter).unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::registry().with(filter).with(layer).init();
    ring
}

struct ConsoleLayer {
    ring: LogRing,
}

impl<S: Subscriber> Layer<S> for ConsoleLayer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let level = *event.metadata().level();
        let record = LogRecord {
            time: SystemTime::now(),
            level,
            target: event.metadata().target().to_owned(),
            message: visitor.finish(),
        };

        let prefix = match level {
            Level::ERROR => "error: ",
            Level::WARN => "warning: ",
            _ => "",
        };
        let uptime = rustix::time::clock_gettime(rustix::time::ClockId::Boottime);
        let line = format!(
            "[{:5}.{:06}] dust-init: {prefix}{}\n",
            uptime.tv_sec,
            uptime.tv_nsec / 1000,
            record.message
        );
        // PID 1's stderr is /dev/console. A failed console write must never take dust-init down.
        let _ = std::io::stderr().lock().write_all(line.as_bytes());
        self.ring.push(record);
    }
}

#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    fn finish(self) -> String {
        if self.fields.is_empty() {
            self.message
        } else if self.message.is_empty() {
            self.fields.trim_start().to_owned()
        } else {
            self.message + &self.fields
        }
    }
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else if value.contains(char::is_whitespace) || value.is_empty() {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(message: &str) -> LogRecord {
        LogRecord {
            time: SystemTime::now(),
            level: Level::INFO,
            target: "dust_init".into(),
            message: message.into(),
        }
    }

    #[test]
    fn ring_keeps_the_most_recent_entries() {
        let ring = LogRing::new();
        for i in 0..CAPACITY + 10 {
            ring.push(record(&i.to_string()));
        }
        let (all, _) = ring.snapshot(0);
        assert_eq!(all.len(), CAPACITY);
        assert_eq!(all[0].message, "10");
        let (tail, _) = ring.snapshot(2);
        let messages: Vec<_> = tail.iter().map(|r| r.message.as_str()).collect();
        assert_eq!(messages, [(CAPACITY + 8).to_string(), (CAPACITY + 9).to_string()]);
    }

    #[test]
    fn subscribers_see_new_entries() {
        let ring = LogRing::new();
        ring.push(record("old"));
        let (past, mut live) = ring.snapshot(0);
        ring.push(record("new"));
        assert_eq!(past.len(), 1);
        assert_eq!(live.try_recv().unwrap().message, "new");
    }
}

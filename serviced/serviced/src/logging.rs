//! serviced's log: on the console, and in memory for its API.
//!
//! Console lines look like `[   12.345678] serviced: message key=value`, with a `warning: ` or
//! `error: ` prefix for those levels, mirroring kernel messages so the serial console reads as
//! one log. Services with `console = true` get `[   12.345678] serviced: [service] line`.

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::layer::Context;

use crate::boot_clock;
use crate::console_writer::ConsoleWriter;
use crate::log_buffer::LogBuffer;

/// The console's writer, once started: before, lines are written right away.
static CONSOLE: OnceLock<ConsoleWriter> = OnceLock::new();

/// Starts the console's writer, then installs the global subscriber, with `filter` (`target=level`
/// directives; `info` if empty or invalid), writing to the console and to `memory`.
pub fn init(filter: &str, memory: Arc<LogBuffer>) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    // PID 1's stderr is `/dev/console`.
    match ConsoleWriter::start(std::io::stderr()) {
        Ok(writer) => {
            let _ = CONSOLE.set(writer);
        }
        Err(e) => console_now(&format!("error: cannot start the console writer: {e}")),
    }
    let filter = Some(filter)
        .filter(|directives| !directives.trim().is_empty())
        .and_then(|directives| directives.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(Level::INFO));
    let layer = LogLayer { memory };
    tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .init();
}

/// Writes `text` to the console as a serviced line, through the console's writer once started:
/// without blocking, but dropped if too many lines wait.
pub fn console(text: &str) {
    let line = console_line(text);
    match CONSOLE.get() {
        Some(writer) => writer.send(line),
        None => write_now(&line),
    }
}

/// Writes `text` to the console as a serviced line right away, blocking: for panics, which may
/// happen anywhere.
pub fn console_now(text: &str) {
    write_now(&console_line(text));
}

/// Waits up to `timeout` for the console's writer to write the lines waiting.
pub fn flush_console(timeout: Duration) {
    if let Some(writer) = CONSOLE.get() {
        writer.flush(timeout);
    }
}

/// `text` as a serviced console line, newline included.
#[must_use]
pub fn console_line(text: &str) -> String {
    let uptime = boot_clock::now();
    format!(
        "[{:5}.{:06}] serviced: {text}\n",
        uptime.as_secs(),
        uptime.subsec_micros()
    )
}

/// Writes `line` to the console (PID 1's stderr). A failed write is ignored: it must never take
/// PID 1 down.
fn write_now(line: &str) {
    use std::io::Write as _;

    let _ = std::io::stderr().lock().write_all(line.as_bytes());
}

/// Writes every event to the console and to memory.
struct LogLayer {
    memory: Arc<LogBuffer>,
}

impl<S: Subscriber> Layer<S> for LogLayer {
    fn on_event(&self, event: &Event<'_>, _context: Context<'_, S>) {
        let mut visitor = MessageVisitor::default();
        event.record(&mut visitor);
        let level = *event.metadata().level();
        let message = visitor.finish();
        let prefix = match level {
            Level::ERROR => "error: ",
            Level::WARN => "warning: ",
            _ => "",
        };
        console(&format!("{prefix}{message}"));
        let pushed = self
            .memory
            .push(level.as_str(), event.metadata().target(), message);
        // Not to its own log: on the console.
        if let Err(e) = pushed {
            console(&format!("error: {e}"));
        }
    }
}

/// Collects an event's message and its other fields, as `key=value`.
#[derive(Default)]
struct MessageVisitor {
    message: String,
    fields: String,
}

impl MessageVisitor {
    /// The message, then the fields.
    #[must_use]
    fn finish(self) -> String {
        if self.fields.is_empty() {
            self.message
        } else if self.message.is_empty() {
            self.fields.trim_start().to_owned()
        } else {
            let mut message = self.message;
            message.push_str(&self.fields);
            message
        }
    }
}

impl Visit for MessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        use std::fmt::Write as _;

        if field.name() == "message" {
            self.message.push_str(value);
        } else if value.contains(char::is_whitespace) || value.is_empty() {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn Debug) {
        use std::fmt::Write as _;

        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

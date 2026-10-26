//! Build progress: each finished unit is a line counting what is done (`[23/85] built tools/meson…`)
//! and, on a terminal, a last line, redrawn, shows what is building and for how long (elsewhere,
//! a line says when a build starts).

use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use crate::recipe::Unit;

pub struct Progress {
    total: usize,
    /// Whether stderr is a terminal, where the status line is drawn.
    terminal: bool,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    done: usize,
    failed: usize,
    running: BTreeMap<Unit, Instant>,
}

impl Progress {
    pub fn new(total: usize) -> Self {
        Self {
            total,
            terminal: std::io::stderr().is_terminal(),
            state: Mutex::default(),
        }
    }

    /// A worker took `unit`: from now on (its environment image included), it is shown running.
    pub fn taken(&self, unit: &Unit) {
        let mut state = self.lock();
        state.running.insert(unit.clone(), Instant::now());
        self.print(&state, "");
    }

    /// A unit starts building: a line where there is no status line to show it.
    pub fn building(&self, message: &str) {
        if !self.terminal {
            eprintln!("{message}");
        }
    }

    pub fn is_running(&self, unit: &Unit) -> bool {
        self.lock().running.contains_key(unit)
    }

    /// `unit` is done (built, cached or skipped), or `failed`.
    pub fn finished(&self, unit: &Unit, failed: bool, message: &str) {
        let mut state = self.lock();
        state.running.remove(unit);
        state.done += 1;
        state.failed += usize::from(failed);
        self.print(&state, message);
    }

    /// Redraws the status line, for the elapsed times.
    pub fn tick(&self) {
        let state = self.lock();
        self.print(&state, "");
    }

    /// Erases the status line, once the builds are over.
    pub fn clear(&self) {
        if self.terminal {
            let _ = write!(std::io::stderr(), "\r\x1b[2K");
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Prints `message` (lines, each counted), then the status line on a terminal.
    fn print(&self, state: &State, message: &str) {
        let mut out = String::new();
        if self.terminal {
            out.push_str("\r\x1b[2K");
        }
        let (done, total) = (state.done, self.total);
        for (i, line) in message.lines().enumerate() {
            if i == 0 {
                out.push_str(&format!("[{done}/{total}] {line}\n"));
            } else {
                out.push_str(&format!("{line}\n"));
            }
        }
        if self.terminal {
            out.push_str(&self.status(state));
        }
        let _ = std::io::stderr().write_all(out.as_bytes());
    }

    /// `  <n> building: <unit> <elapsed> · ... · <n> failed`, cut to the terminal's width: the
    /// counted lines above say how far the build is.
    fn status(&self, state: &State) -> String {
        let running: Vec<String> = (state.running.iter())
            .map(|(unit, started)| format!("{unit} {}", elapsed(started.elapsed())))
            .collect();
        let mut parts = Vec::new();
        if !running.is_empty() {
            parts.push(format!("{} building: {}", running.len(), running.join(" · ")));
        }
        if state.failed > 0 {
            parts.push(format!("{} failed", state.failed));
        }
        let line = format!("  {}", parts.join(" · "));
        let width = (std::env::var("COLUMNS").ok())
            .and_then(|columns| columns.parse().ok())
            .unwrap_or(100usize);
        line.chars().take(width.saturating_sub(1)).collect()
    }
}

/// `42s`, `4m12s`, `1h03m`.
fn elapsed(duration: Duration) -> String {
    let seconds = duration.as_secs();
    match seconds {
        0..60 => format!("{seconds}s"),
        60..3600 => format!("{}m{:02}s", seconds / 60, seconds % 60),
        _ => format!("{}h{:02}m", seconds / 3600, seconds / 60 % 60),
    }
}

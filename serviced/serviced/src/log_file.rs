//! A log file appended to by batches of lines, rotated past its maximum size: the services' logs.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// A log file appended to by batches of lines, moved to `<path>.1` past its maximum size.
pub struct LogFile {
    path: PathBuf,
    max_size: u64,
    file: Option<File>,
    size: u64,
}

impl LogFile {
    /// A closed log file: see [`LogFile::open`].
    #[must_use]
    pub fn new(path: PathBuf, max_size: u64) -> Self {
        Self {
            path,
            max_size,
            file: None,
            size: 0,
        }
    }

    /// Where the log is written.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens the file for appending, readable by everyone.
    pub fn open(&mut self) -> io::Result<()> {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt as _;

        self.file = None;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o644)
            .open(&self.path)?;
        self.size = file.metadata().map_or(0, |m| m.len());
        self.file = Some(file);
        Ok(())
    }

    /// Appends `lines`, each with a newline, in one write, or one per file when the file
    /// outgrows its maximum size on the way and rotates. A failed write is lost; the failures to
    /// rotate or reopen the file are returned.
    #[must_use]
    pub fn append<L: AsRef<[u8]>>(&mut self, lines: &[L]) -> Vec<LogFileError> {
        let mut errors = Vec::new();
        let mut bytes = Vec::new();
        for line in lines {
            let line = line.as_ref();
            if self.full(bytes.len() as u64, line.len() as u64 + 1) {
                self.write(&bytes);
                bytes.clear();
                if let Err(e) = self.rotate() {
                    errors.push(LogFileError::Rotate(e));
                }
                if let Err(e) = self.open() {
                    errors.push(LogFileError::Open(e));
                }
            }
            bytes.extend_from_slice(line);
            bytes.push(b'\n');
        }
        self.write(&bytes);
        errors
    }

    /// Whether adding `more` bytes to the open, non-empty file (once `unwritten` more are
    /// written) would make it outgrow its maximum size.
    #[must_use]
    fn full(&self, unwritten: u64, more: u64) -> bool {
        let size = self.size + unwritten;
        self.file.is_some() && size > 0 && size + more > self.max_size
    }

    /// Closes the file and moves it to `<path>.1`; [`LogFile::open`] starts a new one.
    fn rotate(&mut self) -> io::Result<()> {
        self.file = None;
        let mut rotated = self.path.as_os_str().to_owned();
        rotated.push(".1");
        std::fs::rename(&self.path, rotated)
    }

    /// Writes `bytes`, if the file is open and there are any.
    fn write(&mut self, bytes: &[u8]) {
        use std::io::Write as _;

        if let Some(file) = &mut self.file
            && !bytes.is_empty()
            && file.write_all(bytes).is_ok()
        {
            self.size += bytes.len() as u64;
        }
    }
}

/// Why a log file could not go on.
#[derive(Debug, thiserror::Error)]
pub enum LogFileError {
    /// It could not be moved aside.
    #[error("cannot rotate the log: {0}")]
    Rotate(io::Error),
    /// It could not be (re)opened.
    #[error("cannot open the log: {0}")]
    Open(io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_files_rotate() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.log");
        let mut log = LogFile::new(path.clone(), 12);
        log.open().unwrap();
        let errors = log.append(&["first", "second", "third"]);
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            std::fs::read_to_string(dir.path().join("web.log.1")).unwrap(),
            "second\n"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "third\n");
    }

    #[test]
    fn batches_rotate_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("web.log");
        std::fs::write(&path, "old\n").unwrap();
        let mut log = LogFile::new(path.clone(), 16);
        log.open().unwrap();
        // "old\n1\n2\n3\n4\n5\n" (14 bytes), then "6\n" would make 16: still fits.
        assert!(log.append(&["1", "2", "3", "4", "5", "6"]).is_empty());
        assert!(log.append(&["7", "8", "9"]).is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.path().join("web.log.1")).unwrap(),
            "old\n1\n2\n3\n4\n5\n6\n"
        );
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "7\n8\n9\n");
    }
}

//! Replacing service files atomically (controllers-helpers has the services' own, for their
//! files: libserviced only interfaces with serviced).

use std::fs;
use std::fs::OpenOptions;
use std::fs::Permissions;
use std::io;
use std::io::ErrorKind;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

/// Replaces `path` with `contents`, mode `mode`, through `.<name>.tmp` beside it renamed over it:
/// a reader never sees a partial file. Its directory must exist.
///
/// Only `open`, `write` and `rename`, which sandboxes allow: `fchmod` only when the umask or a
/// stale temporary file left another mode, and no `unlink` or `mkdir`. No `fsync`: a crash keeps
/// the old file or the new one.
///
/// # Errors
///
/// When `path` has no file name, or the file cannot be written.
pub(crate) fn write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let Some(name) = path.file_name() else {
        return Err(io::Error::new(
            ErrorKind::InvalidInput,
            format!("{} is not a file path", path.display()),
        ));
    };
    let temporary = path.with_file_name(format!(".{}.tmp", name.display()));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&temporary)?;
    if file.metadata()?.permissions().mode() & 0o7777 != mode {
        file.set_permissions(Permissions::from_mode(mode))?;
    }
    file.write_all(contents)?;
    fs::rename(&temporary, path)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::MetadataExt;

    use super::*;

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn replaces_with_the_mode_whatever_was_there() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write(&path, b"one", 0o644).unwrap();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o644);
        fs::write(dir.path().join(".config.toml.tmp"), "left over").unwrap();
        fs::set_permissions(
            dir.path().join(".config.toml.tmp"),
            Permissions::from_mode(0o666),
        )
        .unwrap();
        write(&path, b"two", 0o600).unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), "two");
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert_eq!(names(dir.path()), ["config.toml"], "no temporary file left");
    }

    #[test]
    fn needs_its_directory() {
        let dir = tempfile::tempdir().unwrap();
        assert!(write(&dir.path().join("missing/file"), b"", 0o644).is_err());
        assert!(write(Path::new("/"), b"", 0o644).is_err());
    }
}

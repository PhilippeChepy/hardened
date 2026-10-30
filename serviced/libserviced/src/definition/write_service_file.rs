//! Writing and removing the service files of the runtime and persistent layers: services change
//! them in the layers' directories, then ask serviced to `Reload`.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use toml::Table;

use crate::atomic_file;
use crate::definition;
use crate::definition::{Error, Layer, ServiceName};

/// Writes the file of service `name` in `layer` below `root` (`/` on the machine), once checked:
/// its TOML, and the service it makes merged with its files of the other layers visible here (a
/// sandbox may not see the image's). Atomic, and without `mkdir` or `unlink`, which sandboxes
/// need not allow: serviced skips the hidden temporary file, and never reads half of one.
///
/// # Errors
///
/// The image's layer, an invalid file or service, or a file that cannot be written.
pub fn write_service_file(
    root: &Path,
    layer: Layer,
    name: &ServiceName,
    contents: &str,
) -> Result<(), Error> {
    if layer == Layer::Image {
        return Err(Error::ReadOnly);
    }
    let table: Table = contents
        .parse()
        .map_err(|e| Error::Invalid(format!("not TOML: {e}")))?;
    let mut tables = Vec::new();
    for other in Layer::ALL {
        if other == layer {
            tables.push(table.clone());
        } else if let Some(table) =
            definition::read_service_file(&definition::service_file(&other.dir_in(root), name))?
        {
            tables.push(table);
        }
    }
    definition::merge_service(tables).map_err(|e| Error::Service {
        name: name.clone(),
        source: Box::new(e),
    })?;
    let path = definition::service_file(&layer.dir_in(root), name);
    atomic_file::write(&path, contents.as_bytes(), 0o644)
        .map_err(|source| Error::Write { path, source })
}

/// Removes the file of service `name` in `layer` below `root` (`unlink`); returns whether there
/// was one.
///
/// # Errors
///
/// The image's layer, or a file that cannot be removed.
pub fn remove_service_file(root: &Path, layer: Layer, name: &ServiceName) -> Result<bool, Error> {
    if layer == Layer::Image {
        return Err(Error::ReadOnly);
    }
    let path = definition::service_file(&layer.dir_in(root), name);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(source) => Err(Error::Write { path, source }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Test {
        root: tempfile::TempDir,
    }

    impl Test {
        fn new() -> Self {
            let root = tempfile::tempdir().unwrap();
            for layer in Layer::ALL {
                fs::create_dir_all(layer.dir_in(root.path())).unwrap();
            }
            Self { root }
        }

        fn path(&self, layer: Layer, name: &str) -> std::path::PathBuf {
            definition::service_file(&layer.dir_in(self.root.path()), &service(name))
        }

        fn write(&self, layer: Layer, name: &str, contents: &str) -> Result<(), Error> {
            write_service_file(self.root.path(), layer, &service(name), contents)
        }
    }

    fn service(name: &str) -> ServiceName {
        name.parse().unwrap()
    }

    #[test]
    fn writes_valid_files_atomically() {
        let test = Test::new();
        fs::write(
            test.path(Layer::Image, "kubelet"),
            "enabled = false\nexec = [\"/usr/bin/kubelet\"]\n",
        )
        .unwrap();
        test.write(Layer::Runtime, "kubelet", "enabled = true\n")
            .unwrap();
        assert_eq!(
            fs::read_to_string(test.path(Layer::Runtime, "kubelet")).unwrap(),
            "enabled = true\n",
            "a drop-in, valid merged over the image's"
        );
        test.write(Layer::Persistent, "web", "exec = [\"/usr/bin/ctr\"]\n")
            .unwrap();
        let entries: Vec<String> = fs::read_dir(Layer::Persistent.dir_in(test.root.path()))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(entries, ["web.toml"], "no temporary file left");

        let remove = |layer, name| remove_service_file(test.root.path(), layer, &service(name));
        assert!(remove(Layer::Runtime, "kubelet").unwrap());
        assert!(!test.path(Layer::Runtime, "kubelet").exists());
        assert!(
            !remove(Layer::Runtime, "kubelet").unwrap(),
            "already gone is fine"
        );
        assert!(matches!(
            remove(Layer::Image, "kubelet"),
            Err(Error::ReadOnly)
        ));
    }

    #[test]
    fn refuses_invalid_files() {
        let test = Test::new();
        assert!(matches!(
            test.write(Layer::Image, "web", "exec = [\"/a\"]\n"),
            Err(Error::ReadOnly)
        ));
        for (contents, why) in [
            ("exec = [", "TOML"),
            (
                "enabled = true\n",
                "a drop-in without a service to merge over",
            ),
            ("exec = [\"ctr\"]\n", "an absolute program"),
            ("exec = [\"/a\"]\nexecstart = 1\n", "known keys"),
        ] {
            assert!(
                matches!(
                    test.write(Layer::Runtime, "web", contents),
                    Err(Error::Invalid(_) | Error::Service { .. })
                ),
                "{why}"
            );
        }
        assert!(
            !test.path(Layer::Runtime, "web").exists(),
            "nothing written"
        );
    }

    #[test]
    fn needs_the_layer_s_directory() {
        let root = tempfile::tempdir().unwrap();
        let error = write_service_file(
            root.path(),
            Layer::Runtime,
            &service("web"),
            "exec = [\"/a\"]\n",
        )
        .unwrap_err();
        assert!(matches!(error, Error::Write { .. }), "{error}");
    }
}

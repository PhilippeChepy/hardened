//! Reading the service layers and merging files of the same name.

use std::collections::BTreeMap;
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use toml::{Table, Value};

use crate::definition::paths::{IMAGE_DIR, PERSISTENT_DIR};
use crate::definition::{Error, RUNTIME_DIR, Service, ServiceName};

/// Where a service file comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Layer {
    /// `/usr/lib/serviced/services`, shipped by the components they run.
    Image,
    /// [`RUNTIME_DIR`], this boot's, written by services.
    Runtime,
    /// `/var/lib/serviced/services`, kept across boots, written by services.
    Persistent,
}

impl Layer {
    /// Every layer, in the order they merge.
    pub const ALL: [Self; 3] = [Self::Image, Self::Runtime, Self::Persistent];

    /// The directory of its service files.
    #[must_use]
    pub fn dir(self) -> &'static Path {
        Path::new(match self {
            Self::Image => IMAGE_DIR,
            Self::Runtime => RUNTIME_DIR,
            Self::Persistent => PERSISTENT_DIR,
        })
    }

    /// The directory of its service files below `root`: `/` on the machine, another in tests.
    #[must_use]
    pub fn dir_in(self, root: &Path) -> PathBuf {
        root.join(self.dir().strip_prefix("/").expect("an absolute directory"))
    }
}

impl From<Layer> for crate::api::Layer {
    fn from(layer: Layer) -> Self {
        match layer {
            Layer::Image => Self::Image,
            Layer::Runtime => Self::Runtime,
            Layer::Persistent => Self::Persistent,
        }
    }
}

/// A service, merged from its files.
#[derive(Debug, Clone, PartialEq)]
pub struct Loaded {
    /// The service its files make once merged.
    pub service: Service,
    /// The layers it has a file in, in order.
    pub layers: Vec<Layer>,
}

/// Reads the services of `layers` (each with its directory, in order; a missing directory has
/// none). Services that cannot be read, merged or deserialized are left out, their errors returned.
#[must_use]
pub fn load(layers: &[(Layer, &Path)]) -> (BTreeMap<ServiceName, Loaded>, Vec<Error>) {
    let mut errors = Vec::new();
    let mut tables: BTreeMap<ServiceName, (Table, Vec<Layer>)> = BTreeMap::new();
    for &(layer, dir) in layers {
        for (name, path) in service_files(dir, &mut errors) {
            let table = match read_table(&path) {
                Ok(table) => table,
                Err(e) => {
                    errors.push(e);
                    continue;
                }
            };
            let (merged, from) = tables.entry(name).or_default();
            merge(merged, table);
            from.push(layer);
        }
    }
    let mut services = BTreeMap::new();
    for (name, (table, layers)) in tables {
        match merge_service([table]) {
            Ok(service) => {
                services.insert(name, Loaded { service, layers });
            }
            Err(e) => errors.push(Error::Service {
                name,
                source: Box::new(e),
            }),
        }
    }
    (services, errors)
}

/// The service the files `tables` make, in the order of their layers: merged and deserialized,
/// which checks it.
pub fn merge_service(tables: impl IntoIterator<Item = Table>) -> Result<Service, Error> {
    use serde::Deserialize as _;

    let mut merged = Table::new();
    for table in tables {
        merge(&mut merged, table);
    }
    Service::deserialize(merged).map_err(|e| Error::Invalid(e.to_string()))
}

/// The file of service `name` in the layer directory `dir`.
#[must_use]
pub fn service_file(dir: &Path, name: &ServiceName) -> PathBuf {
    dir.join(format!("{name}.toml"))
}

/// The table of the service file `path`; `None` if there is none.
pub fn read_service_file(path: &Path) -> Result<Option<Table>, Error> {
    match read_table(path) {
        Ok(table) => Ok(Some(table)),
        Err(Error::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Merges `over` into `base`: tables key by key, recursively; other values replaced.
fn merge(base: &mut Table, over: Table) {
    for (key, value) in over {
        match (base.get_mut(&key), value) {
            (Some(Value::Table(base)), Value::Table(over)) => merge(base, over),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

/// The `*.toml` files of `dir`, by service name. Hidden files (being written) are skipped.
fn service_files(dir: &Path, errors: &mut Vec<Error>) -> Vec<(ServiceName, PathBuf)> {
    let io_error = |source| Error::Io {
        path: dir.to_owned(),
        source,
    };
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            errors.push(io_error(e));
            return Vec::new();
        }
    };
    let mut files = Vec::new();
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(e) => {
                errors.push(io_error(e));
                continue;
            }
        };
        let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
            continue;
        };
        if path.extension().is_none_or(|extension| extension != "toml") || stem.starts_with('.') {
            continue;
        }
        match stem.parse() {
            Ok(name) => files.push((name, path)),
            Err(e) => errors.push(e),
        }
    }
    files.sort();
    files
}

fn read_table(path: &Path) -> Result<Table, Error> {
    let text = fs::read_to_string(path).map_err(|source| Error::Io {
        path: path.to_owned(),
        source,
    })?;
    text.parse().map_err(|source| Error::Toml {
        path: path.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::definition::Restart;

    fn write(dir: &Path, name: &str, text: &str) {
        fs::create_dir_all(dir).unwrap();
        fs::write(dir.join(name), text).unwrap();
    }

    #[test]
    fn layers_merge_by_name() {
        let root = tempfile::tempdir().unwrap();
        let (image, runtime) = (root.path().join("image"), root.path().join("runtime"));
        write(
            &image,
            "kubelet.toml",
            r#"
enabled = false
exec = ["/usr/bin/kubelet"]
requires = ["containerd"]
env.CONFIG = "/etc/kubelet"
"#,
        );
        write(
            &image,
            "containerd.toml",
            "exec = [\"/usr/bin/containerd\"]\n",
        );
        write(
            &runtime,
            "kubelet.toml",
            r#"
enabled = true
exec = ["/usr/bin/kubelet", "--config=/run/kubelet/config.json"]
env.LOG = "info"
"#,
        );
        write(
            &runtime,
            "web.toml",
            "exec = [\"/usr/bin/true\"]\nrestart = \"never\"\n",
        );
        write(&runtime, ".partial.toml", "garbage");
        write(&runtime, "notes.txt", "garbage");

        let (services, errors) = load(&[
            (Layer::Image, &image),
            (Layer::Runtime, &runtime),
            (Layer::Persistent, &root.path().join("missing")),
        ]);
        assert!(errors.is_empty(), "{errors:?}");
        let kubelet = &services["kubelet"];
        assert_eq!(kubelet.layers, [Layer::Image, Layer::Runtime]);
        assert!(kubelet.service.enabled);
        assert_eq!(
            Vec::from(kubelet.service.exec.clone()),
            ["/usr/bin/kubelet", "--config=/run/kubelet/config.json"]
        );
        assert_eq!(
            kubelet.service.requires[0].as_str(),
            "containerd",
            "kept from the image"
        );
        assert_eq!(
            kubelet.service.env.keys().collect::<Vec<_>>(),
            ["CONFIG", "LOG"],
            "tables merge key by key"
        );
        assert_eq!(services["containerd"].service.restart, Restart::Always);
        assert_eq!(services["web"].service.restart, Restart::Never);
        assert_eq!(services.len(), 3);
    }

    #[test]
    fn service_files_merge_and_deserialize() {
        let dir = tempfile::tempdir().unwrap();
        let name: ServiceName = "web".parse().unwrap();
        let path = service_file(dir.path(), &name);
        assert_eq!(path, dir.path().join("web.toml"));
        assert_eq!(read_service_file(&path).unwrap(), None);
        write(dir.path(), "web.toml", "exec = [\"/usr/bin/web\"]\n");
        let image = read_service_file(&path).unwrap().unwrap();
        let drop_in: Table = "enabled = false\n".parse().unwrap();
        let service = merge_service([image.clone(), drop_in]).unwrap();
        assert!(!service.enabled);
        let relative: Table = "exec = [\"web\"]\n".parse().unwrap();
        assert!(merge_service([image, relative]).is_err(), "checked");
        write(dir.path(), "web.toml", "exec = [");
        assert!(read_service_file(&path).is_err());
    }

    #[test]
    fn invalid_services_are_reported_and_skipped() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "relative.toml", "exec = [\"containerd\"]\n");
        write(
            dir.path(),
            "unknown.toml",
            "exec = [\"/a\"]\nexecstart = \"/a\"\n",
        );
        write(
            dir.path(),
            "syscall.toml",
            r#"
exec = ["/a"]
sandbox.user = 1
sandbox.syscalls = ["nope"]
sandbox.limits.memory-mib = 1
sandbox.limits.tasks = 1
sandbox.limits.cpu-millicores = 1
"#,
        );
        write(dir.path(), "Bad.toml", "exec = [\"/a\"]\n");
        write(dir.path(), "good.toml", "exec = [\"/a\"]\n");
        let (services, errors) = load(&[(Layer::Image, dir.path())]);
        let names: Vec<&str> = services.keys().map(ServiceName::as_str).collect();
        assert_eq!(names, ["good"]);
        assert_eq!(errors.len(), 4, "{errors:?}");
        assert!(
            errors
                .iter()
                .any(|e| e.to_string().contains("unknown system call")),
            "{errors:?}"
        );
    }
}

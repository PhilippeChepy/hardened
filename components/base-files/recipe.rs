//! Root filesystem skeleton: merged-/usr layout, os-release and static configuration.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("base-files");

pub struct BaseFiles;

/// Directories that must exist in the read-only root (mount points included).
const DIRECTORIES: &[&str] = &[
    "/usr/bin",
    "/usr/lib",
    "/etc",
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var",
    "/usr/share/hardened/images",
];

/// Merged /usr, and the /etc entries that change at runtime pointing into /run.
const SYMLINKS: &[(&str, &str)] = &[
    ("usr/bin", "/bin"),
    ("usr/bin", "/sbin"),
    ("usr/lib", "/lib"),
    ("usr/lib", "/lib64"),
    ("../run/hardened/resolv.conf", "/etc/resolv.conf"),
    ("../run/hardened/hosts", "/etc/hosts"),
    ("../run/hardened/hostname", "/etc/hostname"),
    ("../usr/lib/os-release", "/etc/os-release"),
];

const FILES: &[(&str, &str)] = &[
    ("/etc/nsswitch.conf", include_str!("files/etc/nsswitch.conf")),
    ("/etc/passwd", include_str!("files/etc/passwd")),
    ("/etc/group", include_str!("files/etc/group")),
];

impl Component for BaseFiles {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            WORKSPACE_VERSION,
            ComponentType::Library,
            "Root filesystem skeleton: merged-/usr layout, os-release and static configuration",
            "Apache-2.0",
            "https://github.com/PhilippeChepy/hardened",
        )
        .purl(format!(
            "pkg:github/PhilippeChepy/hardened@{WORKSPACE_VERSION}#components/base-files"
        ))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        for &directory in DIRECTORIES {
            let location = b.root(directory);
            b.mkdir(&location);
        }
        for &(target, link) in SYMLINKS {
            let location = b.root(link);
            b.symlink(target, &location);
        }
        let version = b.version();
        let os_release = format!(
            "NAME=\"hardened\"\nID=hardened\nVERSION_ID={version}\nPRETTY_NAME=\"hardened {version}\"\n\
             HOME_URL=\"https://github.com/PhilippeChepy/hardened\"\n"
        );
        let os_release_path = b.root("/usr/lib/os-release");
        b.write(&os_release_path, os_release, Mode::FILE);
        for &(path, contents) in FILES {
            let to = b.root(path);
            b.write(&to, contents, Mode::FILE);
        }
        let containerd = include_str!("files/usr/share/hardened/containerd/config.toml")
            .replace("{sandbox}", &super::pause::IMAGE.reference(super::pause::VERSION));
        let config = b.root("/usr/share/hardened/containerd/config.toml");
        b.write(&config, containerd, Mode::FILE);
        Ok(())
    }
}

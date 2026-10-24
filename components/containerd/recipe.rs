//! Container runtime daemon and runc shim.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("containerd");
const VERSION: &str = "2.4.2";
const PACKAGE: &str = "github.com/containerd/containerd/v2";
const SRC: Source = source!(
    formatcp!("https://github.com/containerd/containerd/archive/refs/tags/v{VERSION}.tar.gz"),
    "02cbbecd0ef78a521d124afa791b843ba5458ef206e1f7f017999ff45c80c0b4",
    file = formatcp!("containerd-{VERSION}.tar.gz"),
);

/// Commands built, and where they are installed.
const COMMANDS: &[(&str, &str)] = &[
    ("./cmd/containerd", "/usr/bin/containerd"),
    ("./cmd/containerd-shim-runc-v2", "/usr/bin/containerd-shim-runc-v2"),
];

pub struct Containerd;

impl Component for Containerd {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Application,
            "Container runtime daemon and runc shim",
            "Apache-2.0",
            "https://containerd.io",
        )
        .purl(format!("pkg:golang/{PACKAGE}@v{VERSION}"))
        .cpe(format!("cpe:2.3:a:linuxfoundation:containerd:{VERSION}:*:*:*:*:*:*:*"))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let tree = b.unpack(&SRC);
        let version = formatcp!("v{VERSION}");
        let vars = [
            (formatcp!("{PACKAGE}/version.Version"), version),
            (formatcp!("{PACKAGE}/version.Revision"), version),
            (formatcp!("{PACKAGE}/version.Package"), PACKAGE),
        ];
        for &(package, install) in COMMANDS {
            // Pure Go, no libc; the snapshotters needing C libraries are left out.
            b.go_build(GoBuild {
                tree: &tree,
                package,
                install,
                cgo: Cgo::Disabled,
                tags: &["no_btrfs", "no_devmapper", "no_zfs"],
                vars: &vars,
            });
        }
        Ok(())
    }
}

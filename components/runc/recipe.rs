//! OCI container runtime.

use super::libseccomp;
use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("runc");
const VERSION: &str = "1.5.2";
const SRC: Source = source!(
    formatcp!("https://github.com/opencontainers/runc/archive/refs/tags/v{VERSION}.tar.gz"),
    "b5af44864a830c7032cf4a72efa0c6d44f701873d9507b127be31ad4d1d42ff3",
    file = formatcp!("runc-{VERSION}.tar.gz"),
);

pub struct Runc;

impl Component for Runc {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Application,
            "OCI container runtime",
            "Apache-2.0",
            "https://github.com/opencontainers/runc",
        )
        .purl(format!("pkg:golang/github.com/opencontainers/runc@v{VERSION}"))
        .cpe(format!("cpe:2.3:a:linuxfoundation:runc:{VERSION}:*:*:*:*:*:*:*"))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let tree = b.unpack(&SRC);
        // runc needs cgo (nsexec, libseccomp).
        let sysroot = b.input(&libseccomp::DEVELOPMENT_FILES);
        b.go_build(GoBuild {
            tree: &tree,
            package: ".",
            install: "/usr/bin/runc",
            cgo: Cgo::Enabled { sysroot: Some(sysroot) },
            tags: &["seccomp", "urfave_cli_no_docs"],
            vars: &[("main.version", VERSION), ("main.gitCommit", formatcp!("v{VERSION}"))],
        });
        Ok(())
    }
}

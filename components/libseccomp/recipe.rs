//! Seccomp filter library used by runc.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("libseccomp");
const VERSION: &str = "2.6.1";
const SRC: Source = source!(
    formatcp!("https://github.com/seccomp/libseccomp/releases/download/v{VERSION}/libseccomp-{VERSION}.tar.gz"),
    "501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be",
);
/// Headers, library and pkg-config file, in their staged `/usr` layout.
pub const DEVELOPMENT_FILES: Output = Output::new(NAME, "dev");

pub struct Libseccomp;

impl Component for Libseccomp {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Library,
            "Seccomp filter library used by runc",
            "LGPL-2.1-only",
            "https://github.com/seccomp/libseccomp",
        )
        .purl(format!("pkg:github/seccomp/libseccomp@v{VERSION}"))
        .cpe(format!(
            "cpe:2.3:a:libseccomp_project:libseccomp:{VERSION}:*:*:*:*:*:*:*"
        ))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let src = b.unpack(&SRC);
        b.cmd("./configure")
            .dir(&src)
            .args(["--prefix=/usr", "--libdir=/usr/lib", "--disable-static"])
            .run();
        b.make(&src).run();
        let staged = b.work("install");
        b.cmd("make")
            .dir(&src)
            .arg("install")
            .arg(Arg::from("DESTDIR=").concat(&staged))
            .run();

        let lib = b.root("/usr/lib");
        b.copy(&staged.join("usr/lib/libseccomp.so.2*"), &lib);
        b.strip();
        let development = b.output(&DEVELOPMENT_FILES);
        b.copy(&staged.join("*"), &development);
        Ok(())
    }
}

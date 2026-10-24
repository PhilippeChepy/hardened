//! GNU C library, shared runtime only.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("glibc");
const VERSION: &str = "2.44";
const SRC: Source = source!(
    formatcp!("https://ftp.gnu.org/gnu/glibc/glibc-{VERSION}.tar.xz"),
    "37f600f2bef3c5e8300147059568b2a2e40a7ad6ccc65ce942556d49429cc667",
);

/// Runtime libraries shipped: no headers, static archives, locales, gconv modules or tools.
const LIBRARIES: &[&str] = &[
    "/usr/lib/ld-linux-x86-64.so.2",
    "/usr/lib/libc.so.6",
    "/usr/lib/libm.so.6",
    "/usr/lib/libpthread.so.0",
    "/usr/lib/libdl.so.2",
    "/usr/lib/librt.so.1",
    "/usr/lib/libresolv.so.2",
    "/usr/lib/libutil.so.1",
    "/usr/lib/libnss_files.so.2",
    "/usr/lib/libnss_dns.so.2",
];

pub struct Glibc;

impl Component for Glibc {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Library,
            "GNU C library (shared runtime only)",
            "LGPL-2.1-or-later",
            "https://www.gnu.org/software/libc/",
        )
        .cpe(format!("cpe:2.3:a:gnu:glibc:{VERSION}:*:*:*:*:*:*:*"))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let src = b.unpack(&SRC);
        let build = b.work("build");
        b.mkdir(&build);
        // Merged /usr: everything lives in /usr/lib (/lib and /lib64 are symlinks to it), which
        // is also the dynamic loader's built-in search path, so the image needs no ld.so.cache.
        b.write(
            &build.join("configparms"),
            "slibdir=/usr/lib\nrtlddir=/usr/lib\n",
            Mode::FILE,
        );
        b.cmd(src.join("configure"))
            .dir(&build)
            .args([
                "--prefix=/usr",
                "--libdir=/usr/lib",
                "--libexecdir=/usr/lib",
                "--enable-kernel=6.1",
                "--enable-stack-protector=strong",
                "--enable-bind-now",
                "--enable-fortify-source",
                "--disable-werror",
                "--disable-profile",
                "--disable-nscd",
                "--disable-timezone-tools",
                "--without-selinux",
            ])
            .run();
        b.make(&build).run();
        let staged = b.work("install");
        b.make(&build)
            .arg("install")
            .arg(Arg::from("DESTDIR=").concat(&staged))
            .run();

        for &library in LIBRARIES {
            let to = b.root(library);
            b.install(&staged.join(&library[1..]), &to, Mode::EXECUTABLE);
        }
        b.strip();
        Ok(())
    }
}

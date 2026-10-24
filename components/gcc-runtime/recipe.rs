//! GCC runtime support library (libgcc_s), required by Rust binaries and glibc.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("gcc-runtime");
const VERSION: &str = "16.2.0";
const SRC: Source = source!(
    formatcp!("https://ftp.gnu.org/gnu/gcc/gcc-{VERSION}/gcc-{VERSION}.tar.xz"),
    "e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e",
);

pub struct GccRuntime;

impl Component for GccRuntime {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Library,
            "GCC runtime support library (libgcc_s), required by Rust binaries and glibc",
            "GPL-3.0-or-later WITH GCC-exception-3.1",
            "https://gcc.gnu.org",
        )
        .purl(format!("pkg:generic/gcc@{VERSION}"))
        .cpe(format!("cpe:2.3:a:gnu:gcc:{VERSION}:*:*:*:*:*:*:*"))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let src = b.unpack(&SRC);
        let build = b.work("build");
        b.mkdir(&build);
        // Only libgcc is needed: build the C compiler without bootstrapping, then the target
        // library.
        b.cmd(src.join("configure"))
            .dir(&build)
            .args([
                "--prefix=/usr",
                "--libdir=/usr/lib",
                "--enable-languages=c",
                "--enable-shared",
                "--disable-bootstrap",
                "--disable-multilib",
                "--disable-nls",
                "--disable-libsanitizer",
                "--disable-libquadmath",
                "--disable-libgomp",
                "--disable-libssp",
                "--disable-libatomic",
                "--disable-libitm",
                "--disable-libvtv",
            ])
            .run();
        b.make(&build).arg("all-gcc").run();
        b.make(&build).arg("all-target-libgcc").run();
        let staged = b.work("install");
        b.cmd("make")
            .dir(&build)
            .arg("install-target-libgcc")
            .arg(Arg::from("DESTDIR=").concat(&staged))
            .run();

        // GCC installs it below lib64/ on x86_64, whatever --libdir says.
        let to = b.root("/usr/lib/libgcc_s.so.1");
        b.install(&staged.join("**/libgcc_s.so.1"), &to, Mode::FILE);
        b.strip();
        Ok(())
    }
}

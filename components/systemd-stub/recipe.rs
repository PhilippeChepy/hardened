//! UEFI stub of the unified kernel image (systemd-stub) and the ukify assembler. Nothing else
//! from systemd ships.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("systemd-stub");
const VERSION: &str = "262.1";
const SRC: Source = source!(
    formatcp!("https://github.com/systemd/systemd/archive/refs/tags/v{VERSION}.tar.gz"),
    "100fc873b848b9b0297d8a705e8e2ed326256c8483d9960ee1ffe264c8a5c3e3",
    file = formatcp!("systemd-{VERSION}.tar.gz"),
);
pub const STUB: Output = Output::new(NAME, "linuxx64.efi.stub");
pub const UKIFY: Output = Output::new(NAME, "ukify");

pub struct SystemdStub;

impl Component for SystemdStub {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Firmware,
            "UEFI stub of the unified kernel image (systemd-stub) and the ukify assembler; nothing else from systemd ships",
            "LGPL-2.1-or-later",
            "https://systemd.io",
        )
        .purl(format!("pkg:github/systemd/systemd@v{VERSION}"))
        .cpe(format!("cpe:2.3:a:systemd_project:systemd:{VERSION}:*:*:*:*:*:*:*"))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let src = b.unpack(&SRC);
        let build = b.work("build");
        b.cmd("meson")
            .dir(&src)
            .arg("setup")
            .arg(&build)
            .args([
                "-Dmode=release",
                "-Dauto_features=disabled",
                "-Dbootloader=enabled",
                "-Defi=true",
                "-Dtests=false",
                "-Dman=disabled",
                "-Dhtml=disabled",
            ])
            .run();
        b.cmd("ninja")
            .arg("-C")
            .arg(&build)
            .arg("src/boot/linuxx64.efi.stub")
            .run();
        let stub = b.output(&STUB);
        b.install(&build.join("src/boot/linuxx64.efi.stub"), &stub, Mode::FILE);
        let ukify = b.output(&UKIFY);
        b.install(&src.join("src/ukify/ukify.py"), &ukify, Mode::EXECUTABLE);
        Ok(())
    }
}

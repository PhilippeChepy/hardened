//! dust-init (PID 1) and dust-api (the mTLS API, run by dust-init as a sandboxed process), built
//! from this repository.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("dust");

pub struct Dust;

impl Component for Dust {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            WORKSPACE_VERSION,
            ComponentType::Application,
            "dust-init (PID 1) and dust-api (sandboxed mTLS API)",
            "Apache-2.0",
            "https://github.com/PhilippeChepy/hardened",
        )
        .purl(format!(
            "pkg:github/PhilippeChepy/hardened@{WORKSPACE_VERSION}#crates/dust-init"
        ))
    }

    fn local(&self) -> Vec<&'static str> {
        vec!["Cargo.toml", "Cargo.lock", ".cargo", "crates"]
    }

    fn fetch(&self, b: &mut Build) -> anyhow::Result<()> {
        b.cargo_fetch();
        Ok(())
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        b.cargo_build(&[
            CargoBinary {
                package: "dust-init",
                install: "/usr/bin/dust-init",
            },
            CargoBinary {
                package: "dust-api",
                install: "/usr/bin/dust-api",
            },
        ]);
        b.strip();
        Ok(())
    }
}

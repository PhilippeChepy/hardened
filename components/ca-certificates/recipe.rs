//! Mozilla CA certificate bundle, as extracted by the curl project.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("ca-certificates");
const VERSION: &str = "2026-10-20";
const BUNDLE: Source = source!(
    formatcp!("https://curl.se/ca/cacert-{VERSION}.pem"),
    "796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe",
);

pub struct CaCertificates;

impl Component for CaCertificates {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Library,
            "Mozilla CA certificate bundle, as extracted by the curl project",
            "MPL-2.0",
            "https://curl.se/docs/caextract.html",
        )
        .purl(format!("pkg:generic/mozilla-ca-certificates@{VERSION}"))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        let bundle = b.source(&BUNDLE);
        let to = b.root("/etc/ssl/certs/ca-certificates.crt");
        b.install(&bundle, &to, Mode::FILE);
        Ok(())
    }
}

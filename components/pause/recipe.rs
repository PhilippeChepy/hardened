//! The Kubernetes pause process: PID 1 of every pod sandbox. Shipped as the "from scratch"
//! `localhost/hardened/pause` image, the sandbox image of containerd's CRI plugin.

use crate::recipe::prelude::*;

pub const NAME: ComponentName = name!("pause");
/// The pause version, and the Kubernetes release its source comes from.
pub const VERSION: &str = "3.10.2";
const KUBERNETES: &str = "v1.37.1";
const SRC: Source = source!(
    formatcp!("https://raw.githubusercontent.com/kubernetes/kubernetes/{KUBERNETES}/build/pause/linux/pause.c"),
    "14a3fe21ab5f8e62937a2b453e76f3b94b0d3c7c04c3d09bc37195f54c1695ea",
    file = formatcp!("pause-{KUBERNETES}.c"),
);
/// The sandbox image: the static pause binary, nothing else.
pub const IMAGE: ContainerImage = ContainerImage {
    name: NAME,
    entrypoint: "/pause",
    user: (65535, 65535),
};

pub struct Pause;

impl Component for Pause {
    fn meta(&self) -> Meta {
        Meta::new(
            NAME,
            VERSION,
            ComponentType::Application,
            "Kubernetes pause process, PID 1 of pod sandboxes (statically linked)",
            "Apache-2.0",
            "https://github.com/kubernetes/kubernetes/tree/master/build/pause",
        )
        .purl(format!("pkg:generic/kubernetes-pause@{VERSION}"))
    }

    fn build(&self, b: &mut Build) -> anyhow::Result<()> {
        // Static, as upstream builds it: the pause image contains nothing but this binary.
        let source = b.source(&SRC);
        let binary = b.work("pause");
        b.cmd("gcc")
            .args(["-Os", "-Wall", "-Werror", "-static", "-s"])
            .arg(formatcp!("-DVERSION=v{VERSION}"))
            .arg("-o")
            .arg(&binary)
            .arg(&source)
            .run();
        b.record_static_runtime();
        let image = b.container_image(&IMAGE);
        b.install(&binary, &image.join("pause"), Mode::EXECUTABLE);
        Ok(())
    }
}

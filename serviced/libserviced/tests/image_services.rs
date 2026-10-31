//! The service files the image ships parse.

#![allow(
    clippy::expect_used,
    clippy::unwrap_used,
    reason = "a test: a failure is the test's"
)]
use std::path::Path;

use libserviced::definition;
use libserviced::definition::Layer;

#[test]
fn image_services_are_valid() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../specs/targets");
    let dirs = [
        root.join("standard/components/system-controllers/services"),
        root.join("standard/components/containerd/services"),
        root.join("kubernetes-1-37/components/kubelet/services"),
        root.join("kubernetes-1-37/components/kubelet-controller/services"),
    ];
    let layers: Vec<(Layer, &Path)> = dirs
        .iter()
        .map(|dir| (Layer::Image, dir.as_path()))
        .collect();
    let (services, errors) = definition::load(&layers);
    assert!(errors.is_empty(), "invalid service files: {errors:#?}");
    for name in [
        "network-controller",
        "machine-controller",
        "storage-controller",
        "time-controller",
        "trust-controller",
        "workload-controller",
        "machine-apiproxy",
        "containerd",
        "kubelet",
        "kubelet-controller",
    ] {
        assert!(services.contains_key(name), "{name} is missing");
    }
    for (name, loaded) in &services {
        let service = &loaded.service;
        let socket_callers = service.sockets.iter().flat_map(|socket| &socket.allow);
        for other in service.requires.iter().chain(socket_callers) {
            assert!(
                services.contains_key(other),
                "{name} names {other}, which is missing"
            );
        }
    }
}

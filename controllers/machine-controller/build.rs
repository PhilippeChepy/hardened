//! Compiles the machine's API with `protox`, so no `protoc` binary is required.
//!
//! Its messages carry the controllers' and machine-apiproxy's: their protos are read from their
//! crates, and their generated types used from there rather than generated again.

/// The packages the machine's API imports, each with its proto directory and its Rust module.
const IMPORTED: [(&str, &str, &str); 6] = [
    (
        ".hardened.apiproxy.v1",
        "../machine-apiproxy/proto",
        "::machine_apiproxy::apiproxy",
    ),
    (
        ".hardened.kubelet.v1",
        "../kubelet-controller/proto",
        "::kubelet_controller::kubelet",
    ),
    (
        ".hardened.network.v1",
        "../network-controller/proto",
        "::network_controller::network",
    ),
    (
        ".hardened.storage.v1",
        "../storage-controller/proto",
        "::storage_controller::storage",
    ),
    (
        ".hardened.time.v1",
        "../time-controller/proto",
        "::time_controller::time",
    ),
    (
        ".hardened.workloads.v1",
        "../workload-controller/proto",
        "::workload_controller::workloads",
    ),
];

const PROTO: &str = "hardened/machine/v1/machine.proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let includes = ["proto"]
        .into_iter()
        .chain(IMPORTED.map(|(_, directory, _)| directory));
    let mut file_descriptors = protox::compile([PROTO], includes)?;
    // The imported files' messages are extern, but their services would still be generated.
    for file in &mut file_descriptors.file {
        if file.name() != PROTO {
            file.service.clear();
        }
    }
    let mut config = tonic_prost_build::configure().include_file("hardened.rs");
    for (package, _, module) in IMPORTED {
        config = config.extern_path(package, module);
    }
    config.compile_fds(file_descriptors)?;
    println!("cargo:rerun-if-changed=proto");
    for (_, directory, _) in IMPORTED {
        println!("cargo:rerun-if-changed={directory}");
    }
    Ok(())
}

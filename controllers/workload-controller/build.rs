//! Compiles workload-controller's APIs with `protox`, so no `protoc` binary is required.

const CONSOLE_PROTO: &str = "../workload-console/proto";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file_descriptors = protox::compile(
        [
            "hardened/workload/v1/workload.proto",
            "hardened/workloads/v1/workloads.proto",
        ],
        ["proto", CONSOLE_PROTO],
    )?;
    // Extern messages, but their service would still be generated.
    for file in &mut file_descriptors.file {
        if file.package() == "hardened.console.v1" {
            file.service.clear();
        }
    }
    tonic_prost_build::configure()
        .extern_path(".hardened.console.v1", "::workload_console::console")
        .include_file("hardened.rs")
        .compile_fds(file_descriptors)?;
    println!("cargo:rerun-if-changed=proto");
    println!("cargo:rerun-if-changed={CONSOLE_PROTO}");
    Ok(())
}

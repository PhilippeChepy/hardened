//! Compiles workload-console's API with `protox`, so no `protoc` binary is required.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_descriptors = protox::compile(["hardened/console/v1/console.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .include_file("hardened.rs")
        .compile_fds(file_descriptors)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}

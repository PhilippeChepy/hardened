//! Compiles firewall-controller's API with `protox`, so no `protoc` binary is required.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_descriptors = protox::compile(["hardened/firewall/v1/firewall.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .include_file("hardened.rs")
        .compile_fds(file_descriptors)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}

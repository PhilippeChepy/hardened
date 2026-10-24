//! Compiles the dust API with `protox`, so no `protoc` binary is required.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(["hardened/v1/dust.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .include_file("hardened.rs")
        .compile_fds(fds)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}

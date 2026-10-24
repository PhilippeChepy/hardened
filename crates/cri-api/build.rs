//! Compiles the vendored CRI proto with `protox`, so no `protoc` binary is required.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fds = protox::compile(["runtime/v1/api.proto"], ["proto"])?;
    tonic_prost_build::configure()
        .build_server(false)
        .include_file("cri.rs")
        .compile_fds(fds)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}

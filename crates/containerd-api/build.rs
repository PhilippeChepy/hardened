//! Compiles the vendored containerd protos with `protox`, so no `protoc` binary is required.

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from("proto");
    let mut protos = Vec::new();
    collect(&root, &mut protos)?;
    protos.sort();

    let fds = protox::compile(&protos, [&root])?;
    let mut config = prost_build::Config::new();
    // Required by `to_any`: containerd identifies `Any` payloads by their full message name.
    config.enable_type_names();
    tonic_prost_build::configure()
        .build_server(false)
        .include_file("containerd.rs")
        .compile_fds_with_config(fds, config)?;

    println!("cargo:rerun-if-changed=proto");
    Ok(())
}

fn collect(dir: &PathBuf, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "proto") {
            out.push(path.strip_prefix("proto").unwrap().to_path_buf());
        }
    }
    Ok(())
}

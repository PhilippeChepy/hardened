//! Compiles trust-controller's APIs with `protox`, so no `protoc` binary is required.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let file_descriptors = protox::compile(
        [
            "hardened/trust/v1/trust.proto",
            "hardened/attestation/v1/attestation.proto",
        ],
        ["proto"],
    )?;
    tonic_prost_build::configure()
        // A `Bytes` the secret's owner wipes once the message is encoded and dropped.
        .bytes(".hardened.trust.v1.Secret.secret")
        .include_file("hardened.rs")
        .compile_fds(file_descriptors)?;
    println!("cargo:rerun-if-changed=proto");
    Ok(())
}

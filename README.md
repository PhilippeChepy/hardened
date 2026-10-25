# hardened

A minimal, immutable cloud operating system for running containers.

The image contains a Linux kernel booted as a signed unified kernel image (UKI), containerd and
runc: all built with LLVM, statically linked against musl (with mimalloc as its allocator) and
with LTO. It also contains **dust-init**, a Rust PID 1 that replaces both the init system and
cloud-init. There is no systemd, no shell, no package manager and no SSH: the machine is
configured through user-data and managed through an mTLS API.

Inspired by [Bottlerocket](https://github.com/bottlerocket-os/bottlerocket),
[Talos](https://github.com/siderolabs/talos) and
SKS templates (the SKS node operating system I initiated as an engineer working at Exoscale, currently private repository).

```text
UEFI ─▶ UKI (systemd-stub + kernel + cmdline with the dm-verity root hash, signed)
         └─▶ kernel: dm-init opens the verity root (erofs), no initramfs
              └─▶ dust-init (PID 1)
                   ├─ mounts, sysctls, signed kernel modules (from the verity root only)
                   ├─ DHCP, platform metadata, user-data
                   ├─ /var: state partition, grown to fill the disk
                   ├─ containerd (CRI) ──▶ pods: workloads (user-data or API)
                   ├─ control API on a unix socket, vTPM attestation evidence
                   └─ dust-api (mTLS, sandboxed process)
```

## Features

- **Immutable root.** The root filesystem is read-only erofs protected by dm-verity. Its root
  hash sits in the signed UKI command line, so every byte executed is measured. To upgrade,
  replace the VM.
- **Built from source.** Every component in the image, and every tool that builds it (LLVM,
  musl, Rust, Go...), is compiled from pinned, checksummed sources. Only the
  bootstrap comes from outside: StageX images, pinned by digest, themselves built from a
  full-source bootstrap. The build outputs a qcow2 image and a CycloneDX SBOM that includes the
  Go modules and Rust crates linked into each binary.
- **Small attack surface.** The kernel only loads signed modules, and only from the dm-verity
  root (LoadPin), firmware included. Modules are signed with a persistent key, so builds stay
  reproducible. The lockdown LSM runs in integrity mode, and legacy syscalls and io_uring are
  disabled. Nothing in the image is setuid.
- **Platforms.** Exoscale, and qemu for local testing.
- **Remote attestation.** dust-init can serve PCRs, the TCG event log, and TPM2 quotes signed by a
  restricted attestation key. TPM 2.0 commands are encoded by hand, with no TSS library.

## Quick start

Building requires Linux on x86_64, `podman` (rootless is fine), a Rust toolchain for `cargo builder`
and about 20 GB of disk space. `/dev/kvm` is optional; without it the VM runs under emulation and
is much slower.

```sh
cargo builder image       # build the standard target's components, then its image  →  build/out/
cargo builder run         # boot it in qemu (OVMF + swtpm), serial console on stdio
cargo builder test        # boot it headless and wait for the smoke-test markers
```

The first build compiles the whole toolchain from source (LLVM twice, musl, Rust, Go...), then the image's components, which can take some time. Later builds are incremental: each
component is cached, keyed by a hash of all its inputs.

`build/out/` contains, for the standard target (named `hardened`; `--target` picks another of
[specs/targets/](specs/targets/)):

| File | Content |
| --- | --- |
| `hardened-<version>-x86_64.qcow2` | Disk image to upload to a cloud |
| `hardened-<version>-x86_64.cdx.json` | CycloneDX 1.6 SBOM |
| `hardened-<version>-x86_64.manifest.json` | Every file in the root filesystem, its checksum and owning component |
| `hardened-<version>-x86_64.efi` | Signed UKI |
| `hardened-<version>-x86_64.roothash` | dm-verity root hash |

### Running workloads

User-data (TOML, optionally gzip and/or base64) declares workloads:

```toml
[settings.containers.web]
image = "docker.io/library/nginx:1.29"
restart = "always"
```

To use the API, generate a PKI and add the `[settings.api]` snippet that `hctl pki user-data`
prints to your user-data:

```sh
cargo run -p hctl -- pki init --out pki --server-ip 127.0.0.1
cargo run -p hctl -- pki user-data --dir pki >> user-data.toml
cargo builder run --user-data user-data.toml

# Second terminal: point hctl at the PKI directory (it holds ca.pem, client.pem and client-key.pem)
export HCTL_CONFIG_DIR=pki
cargo run -p hctl -- --endpoint 127.0.0.1 version
cargo run -p hctl -- workloads apply hello --image docker.io/library/busybox:1.37 --command sleep --arg 3600
cargo run -p hctl -- attest quote --nonce $(openssl rand -hex 32)
```

See [docs/user-data.md](docs/user-data.md) for every setting.

## Repository layout

| Path | Content |
| --- | --- |
| [specs/components/](specs/components/) | The recipes several targets build (make, CMake, Python, LLVM), which a target may override |
| [specs/targets/](specs/targets/) | The build pipeline: each target (bootstrap on the pinned StageX seed, `tools`, the images) with the recipes of its components |
| [crates/dust-builder/](crates/dust-builder/) | The build system: fetch, build, assemble, seal, sign, SBOM, run |
| [crates/dust-init/](crates/dust-init/) | PID 1 |
| [crates/dust-api/](crates/dust-api/) | mTLS API proxy, run by dust-init in a sandbox |
| [crates/dust-proto/](crates/dust-proto/) | API definition (gRPC) |
| [crates/hctl/](crates/hctl/) | Operator CLI and PKI helper |
| [crates/containerd-api/](crates/containerd-api/) | containerd gRPC bindings for the image import only (streaming, transfer, snapshots) |
| [docs/](docs/) | Architecture and user-data reference |

## Documentation

- [Architecture](docs/architecture.md): boot flow, disk layout, build system, security model.
- [User-data reference](docs/user-data.md).

## License

Apache-2.0. Components in the image keep their own licenses, which are listed in the SBOM.

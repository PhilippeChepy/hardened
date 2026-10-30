# hardened

A minimal, immutable cloud operating system for running containers.

The image contains a Linux kernel booted as a signed unified kernel image (UKI), containerd and
runc: all built with LLVM, statically linked against musl (with mimalloc as its allocator) and
with LTO. It also contains **serviced**, a PID 1 supervising services (each declaring its
dependencies, sandbox and API socket), and the controllers replacing cloud-init and the usual
daemons. There is no systemd, no shell, no package manager and no SSH: the machine is configured
through user-data and managed through an mTLS API.

Inspired by [Bottlerocket](https://github.com/bottlerocket-os/bottlerocket),
[Talos](https://github.com/siderolabs/talos) and the SKS templates (the SKS node operating system
I initiated as an engineer at Exoscale, in a private repository).

```text
UEFI ─▶ UKI (systemd-stub + kernel + cmdline with the dm-verity root hash, signed)
         └─▶ kernel: dm-init opens the verity root (erofs), no initramfs
              └─▶ serviced (PID 1): mounts, LoadPin, hardened sysctls, reaping, power, services
                   ├─ network-controller (DHCP, sandboxed)
                   │  └─ machine-controller: platform metadata, user-data, sysctls, signed kernel
                   │     │  modules (from the verity root only); configures the controllers
                   │     │  through their APIs, and serves the machine's API
                   │     ├─ storage-controller: /var, the state partition grown to fill the disk
                   │     │  (optionally LUKS2, key sealed through trust-controller)
                   │     ├─ time-controller (SNTP client, sandboxed, CAP_SYS_TIME only)
                   │     ├─ trust-controller (the vTPM: attestation, sealing; sandboxed)
                   │     ├─ workload-controller: the workload-<name> services (sandboxed)
                   │     │  └─ workload-console: hctl workloads exec, through ctr tasks exec
                   │     └─ machine-apiproxy (the machine's API over mTLS, sandboxed)
                   └─ containerd, once /var is mounted
                      └─ workload-<name>: ctr pull, ctr run (user-data or API)
```

## Features

- **Immutable root.** The root filesystem is read-only erofs protected by dm-verity. Its root
  hash sits in the signed UKI command line, so every byte executed is measured. To upgrade,
  replace the VM.
- **Built from source.** Every component in the image, and every tool that builds it (LLVM,
  musl, Rust, Go...), is compiled from pinned, checksummed sources. Only the bootstrap comes from
  outside: StageX images, pinned by digest, themselves built from a full-source bootstrap. The
  build outputs a qcow2 image and a CycloneDX SBOM that includes the Go modules and Rust crates
  linked into each binary.
- **Small attack surface.** The kernel only loads signed modules, and only from the dm-verity
  root (LoadPin), firmware included. Modules are signed with a persistent key, so builds stay
  reproducible. The lockdown LSM runs in integrity mode, and legacy syscalls and io_uring are
  disabled. Nothing in the image is setuid.
- **Platforms.** Exoscale, and qemu for local testing.
- **Remote attestation.** trust-controller serves PCRs, the TCG event log, and TPM2 quotes signed
  by a restricted attestation key. TPM 2.0 commands are encoded by hand, with no TSS library.
- **Encrypted state, optionally.** With `settings.hardened.storage.encryption = "tpm"`, `/var` is
  LUKS2, its key sealed to the vTPM and to the booted image (PCR 11): a copy of the disk is
  unreadable ([docs/state-encryption.md](docs/state-encryption.md)).

## Quick start

Building requires Linux on x86_64, `podman` (rootless is fine), a Rust toolchain for
`cargo builder` and about 20 GB of disk space. `/dev/kvm` is optional; without it the VM runs
under emulation, much slower.

```sh
cargo builder image   # build the standard target's components, then its image → build/out/
cargo builder run     # boot it in qemu (OVMF + swtpm), serial console on stdio
cargo builder test    # boot it headless (6 boots on one disk), wait for the smoke-test markers
```

[docs/local-testing.md](docs/local-testing.md) explains these commands and their options.

The first build compiles the whole toolchain from source (LLVM twice, musl, Rust, Go...), then the
image's components, which takes a while. Later builds are incremental: each component is cached,
keyed by a hash of all its inputs.

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

User-data (TOML, optionally gzip and/or base64; Bottlerocket's keys for the settings it shares with
Bottlerocket) declares workloads:

```toml
[settings.hardened.containers.web]
image = "docker.io/library/nginx:1.29"
restart = "always"
```

To use the API, generate a PKI and add the `[settings.hardened.api]` section that
`hctl pki user-data` prints to your user-data:

```sh
cargo run --manifest-path controllers/Cargo.toml -p hctl -- pki init --out pki --server-ip 127.0.0.1
cargo run --manifest-path controllers/Cargo.toml -p hctl -- pki user-data --dir pki >> user-data.toml
cargo builder run --user-data user-data.toml

# Second terminal: point hctl at the PKI directory (it holds ca.pem, client.pem and client-key.pem)
export HCTL_CONFIG_DIR=pki
cargo run --manifest-path controllers/Cargo.toml -p hctl -- --endpoint 127.0.0.1 version
cargo run --manifest-path controllers/Cargo.toml -p hctl -- workloads apply hello --image docker.io/library/busybox:1.37 -- sleep 3600
cargo run --manifest-path controllers/Cargo.toml -p hctl -- attest quote --nonce $(openssl rand -hex 32)
```

See [docs/user-data.md](docs/user-data.md) for every setting.

### Kubernetes nodes

The `kubernetes-1-37` target (`cargo builder image --target kubernetes-1-37`) adds kubelet 1.37,
the CNI plugins, iptables and nft. With
[`settings.kubernetes`](docs/user-data.md#settingskubernetes) in its user-data (the API server,
the cluster CA and a bootstrap token), the machine joins the cluster as a node; workloads keep
running beside the pods. See [docs/kubernetes-target.md](docs/kubernetes-target.md).

## Repository layout

The Rust code is in three Cargo workspaces, each with its `Cargo.lock`: `serviced/`,
`controllers/` (with libserviced as a path dependency) and `image-builder/`.

| Path | Content |
| --- | --- |
| [specs/components/](specs/components/) | The recipes several targets build (make, CMake, Python, LLVM), which a target may override |
| [specs/targets/](specs/targets/) | The build pipeline: each target (bootstrap on the pinned StageX seed, `tools`, `image-tools`, the images) with the recipes of its components |
| [image-builder/](image-builder/) | The build system: fetch, build, assemble, seal, sign, SBOM, run |
| [serviced/serviced/](serviced/serviced/) | PID 1: the service supervisor, its sandboxes and its API |
| [serviced/libserviced/](serviced/libserviced/) | What a service needs from serviced: the service file format, its layers and the services' log paths; its API, notify, socket activation, caller authorization |
| [controllers/network-controller/](controllers/network-controller/) | DHCP client and resolver configuration; its library: its API and `settings.dns` |
| [controllers/machine-controller/](controllers/machine-controller/) | Instance setup from metadata and user-data, the controllers' configuration, the machine's API; its library: the machine's API (`hardened.machine.v1`), the settings model and user-data parsing |
| [controllers/storage-controller/](controllers/storage-controller/) | The state partition on `/var`, optionally encrypted; its library: its API and `settings.hardened.storage` |
| [controllers/time-controller/](controllers/time-controller/) | SNTP client; its library: its API and its time servers |
| [controllers/trust-controller/](controllers/trust-controller/) | The TPM's only user, with its TPM 2.0 client: attestation evidence and sealing; its library: their APIs |
| [controllers/workload-controller/](controllers/workload-controller/) | Workloads as `workload-<name>` services; its library: its APIs (`hardened.workload.v1`, `hardened.workloads.v1`) and the workloads' model |
| [controllers/workload-console/](controllers/workload-console/) | Processes run in workloads' containers (`hctl workloads exec`); its library: its API (`hardened.console.v1`) |
| [controllers/kubelet-controller/](controllers/kubelet-controller/) | kubelet's configuration (Kubernetes targets); its library: its API and `settings.kubernetes` |
| [controllers/machine-apiproxy/](controllers/machine-apiproxy/) | The machine's API over mTLS; its library: its API, `settings.hardened.api` and the clients' roles |
| [controllers/controllers-helpers/](controllers/controllers-helpers/) | The validated values several services share, the helpers of their settings and protobuf conversions, and gRPC channels to unix sockets with a forwarder |
| [controllers/hctl/](controllers/hctl/) | Operator CLI and PKI helper |
| [docs/](docs/) | Documentation |

## Documentation

- [Architecture](docs/architecture.md): boot flow, services and their APIs, disk layout, build
  system, security model.
- [Services](docs/services.md): the service file format, and each service of the images.
- [User-data reference](docs/user-data.md).
- [Testing an image locally](docs/local-testing.md): booting it in qemu, using its API, the smoke
  test.
- [Kubernetes target](docs/kubernetes-target.md): its contents, how a node runs, networking,
  versions.
- [State partition encryption](docs/state-encryption.md).
- [The `nvidia` target](docs/nvidia-target.md): planned GPU support, its design.

## License

Apache-2.0. Components in the image keep their own licenses, which are listed in the SBOM.

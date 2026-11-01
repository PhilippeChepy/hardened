# Testing an image locally

`cargo builder` boots images in qemu on your machine, with the virtual hardware of a cloud
instance: UEFI firmware (OVMF), a vTPM (swtpm), virtio disk, network and RNG. User-data comes
through qemu's fw_cfg, which machine-controller reads like a cloud's metadata. qemu, OVMF and swtpm
are not taken from the host: they are components of the `image-tools` target, built from source
like the rest, and run in a podman container of that target's image.

## Requirements

- Linux on x86_64, `podman` (rootless is fine) and a Rust toolchain, as for building.
- `/dev/kvm`, readable and writable by your user, for hardware virtualization. Without it qemu
  emulates the CPU (TCG): it works, but boots take minutes instead of seconds, and
  `cargo builder test` may need a longer `--timeout`.
- Internet access from the VM (through qemu's user-mode network) to pull container images and
  synchronize the clock.

## Booting interactively

```sh
cargo builder image                       # build the image (the standard target by default)
cargo builder run                         # boot it, the serial console on your terminal
cargo builder run --user-data my.toml     # boot it with user-data
```

`run` boots the image last built by `cargo builder image`; it does not rebuild it. Both take
`--target` to pick another target of [specs/targets/](../specs/targets/), such as
`kubernetes-1-37`.

The terminal shows the serial console: the kernel's messages, then serviced's and the services'
log lines (and the output of workloads with `console = true`). There is no shell and no login
prompt: you interact with the machine through its [API](#using-the-api). qemu's console
multiplexer is on: **Ctrl-A X** quits qemu (a power cut, as far as the machine knows), Ctrl-A C
switches to qemu's monitor and back.

Options:

| Option | Default | Effect |
| --- | --- | --- |
| `--user-data FILE` | none | User-data passed to the VM ([reference](user-data.md)); TOML, optionally gzip and/or base64 |
| `--keep-state` | off | Keep the disk, the TPM and the UEFI variables of the previous run, as a reboot would |
| `--disk-size SIZE` | `8G` | Size of the virtual disk; storage-controller grows the state partition to fill it |
| `--memory-mib N` | `2048` | Memory of the VM |
| `--api-port PORT` | `7443` | Host port (on 127.0.0.1) the machine API is forwarded to |

The image itself is never written to: the VM's disk is a qcow2 overlay over it, in `build/run/`,
with the TPM's state and the UEFI variables. Without `--keep-state`, each run starts from a new
disk and a new TPM, as a new instance would.

## Using the API

The machine API (`machine-apiproxy`, mutual TLS on port 7443) is only enabled by user-data. Create
a PKI, whose server certificate is valid for 127.0.0.1, append its `[settings.hardened.api]`
section to your user-data, and boot with it:

```sh
alias hctl='cargo run --quiet --manifest-path controllers/Cargo.toml -p hctl --'
hctl pki init --out pki --server-ip 127.0.0.1
hctl pki user-data --dir pki >> my.toml
cargo builder run --user-data my.toml
```

Then, in another terminal (with the same alias):

```sh
export HCTL_CONFIG_DIR=pki HCTL_ENDPOINT=127.0.0.1   # 127.0.0.1:PORT with --api-port
hctl version                  # the OS and the machine's identity
hctl logs --follow            # serviced's log
hctl settings                 # the effective settings, secrets redacted
hctl storage                  # what backs /var, and why
hctl time                     # clock synchronization
hctl service list             # serviced's services; status, logs, start, stop, restart, reload
hctl service status containerd
hctl workloads apply hello --image public.ecr.aws/docker/library/busybox:1.37 -- sleep 3600
hctl workloads list
hctl workloads logs hello
hctl workloads exec -it hello -- sh   # a shell in the container
hctl workloads apply debug --image public.ecr.aws/docker/library/busybox:1.37 --privileged \
    --host-root /host -- sleep 3600     # the host's / at /host, read-only
hctl attest quote --nonce $(openssl rand -hex 32)
hctl attest ek                                  # the EK's fingerprint, to pin
hctl attest verify --expected build/out/hardened-0.1.0-x86_64.pcrs.json --ek <fingerprint>
hctl reboot                   # or shutdown: a clean stop, unlike Ctrl-A X
```

Workloads applied through the API are persistent: with `--keep-state`, they run again on the next
boot.

## The smoke test

```sh
cargo builder test                          # the standard target
cargo builder test --target kubernetes-1-37
```

`test` builds the image (skip it with `--no-build` to reuse the last one) and a test variant of
it, then boots the VM six times (seven for targets shipping kubelet), headless, on the same disk,
with [tests/smoke-user-data.toml](../tests/smoke-user-data.toml). That user-data encrypts the state
partition with the TPM and runs a short-lived workload that prints to the console, says when it
finds a mark an earlier boot left on `/var`, and leaves its own. Each boot waits for its markers
on the console, then stops the VM abruptly, as a crash would:

| Boot | Disk, TPM | Expected |
| --- | --- | --- |
| 1 | new disk, new TPM | the state partition formatted with encryption, the workload's hello, the clock synchronized |
| 2 | same disk and TPM | the partition unlocked with the TPM, the first boot's mark found |
| 3 | the test variant, same TPM | another image to the TPM (PCR 11 differs): it cannot unseal the key and formats the partition again |
| 4 | the test variant, a cleared TPM | the TPM cannot unseal the key: formatted again |
| 5 | the test variant, no TPM | `/var` on a tmpfs, the partition left alone |
| 6 | the test variant, the TPM back | the partition unlocked, the fourth boot's mark found |
| 7 (targets shipping kubelet) | the image, same TPM | kubelet runs a probe pod and takes its shutdown delay lock; after a reboot through the API, the pod is stopped and kubelet releases its lock before serviced stops the services |

The first boot is also checked through the machine's API: the test builds hctl, creates a PKI in
`build/test-pki` and adds its `[settings.hardened.api]` section to the user-data. Once the boot's
markers are seen, hctl ([`smoke_api.rs`](../image-builder/src/smoke_api.rs)):

- verifies the attestation: the EK pinned by the fingerprint `hctl attest ek` gives, the
  attestation key proven by credential activation, the PCRs against the image's `pcrs.json`;
- checks that containerd is ready;
- applies a privileged workload with the host's root at `/host`, then execs into it: its exit
  code, its standard input, the host's files readable and nowhere writable (`/host`,
  `/host/var`, `/host/run`);
- waits for workload-console to exit once idle, then removes the workload.

The seventh boot adds [tests/smoke-kubernetes-user-data.toml](../tests/smoke-kubernetes-user-data.toml)
to the user-data: a cluster whose API server does not exist (kubelet runs its static pods
without), a 30 s shutdown grace period, and the
[probe pod](../tests/smoke-kubelet-probe.yaml), privileged to write to the kernel's log so that
the console shows it running, then told to stop. Once kubelet holds its lock, the test reboots the
machine with hctl and waits for, in order: kubelet-controller relaying serviced's announcement,
the pod's SIGTERM and its exit, kubelet releasing its lock, and serviced going on with the
shutdown.

The test variant is a second disk holding only an ESP whose UKI adds `hardened.test-variant=1` to
the kernel command line: the machine runs the same root filesystem, but the TPM sees another image.

A boot fails when a marker does not show up within `--timeout` seconds (300 by default), naming
the markers it was still waiting for, or on a kernel panic. The test's VM state is in
`build/test/`, and its API forwarded to port 17443, so it runs beside a `cargo builder run`. It
needs the Internet: the workload's image comes from public.ecr.aws and the clock from
pool.ntp.org.

## When something fails

- **A build step**: each component's and environment's build log is in `build/logs/`.
  `cargo builder plan <component>` prints a component's build without running it, and
  `cargo builder build --force <component>` rebuilds a cached one.
- **A boot**: everything goes to the serial console, which `test` prints as it boots.
  machine-controller logs invalid user-data there and boots with defaults; a service that fails is
  logged by serviced with its exit status.
- **The API does not answer**: check that the user-data has `[settings.hardened.api]`, that the
  console shows machine-apiproxy started, and that `HCTL_ENDPOINT` names the forwarded port.
- **Starting over**: delete `build/run/` or `build/test/`. `build/` is disposable, but
  `build/keys/` holds the Secure Boot and module signing keys, and the randstruct seed: removing it
  changes every image.

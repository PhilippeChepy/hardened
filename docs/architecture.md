# Architecture

## Goals

- **Immutable and verifiable.** Every byte executed on the machine comes from a signed or
  hash-verified artifact. A running machine's root filesystem cannot be changed.
- **Minimal.** The image holds a kernel, a C library, a container runtime, and serviced with the
  few services it runs. Anything else runs in containers.
- **Accountable.** Everything is built from pinned sources by a reproducible pipeline, and the
  build outputs an SBOM covering everything compiled into the image.

## Image contents

| Component | Why it is there | Linking |
| --- | --- | --- |
| Linux 6.18 (longterm) | the kernel, booted as a UKI: KVM/QEMU guest drivers and what Kubernetes and its CNIs need (BTF included), built in from `allnoconfig` | ThinLTO |
| systemd-stub | UEFI stub of the UKI (only the stub ships) | — |
| containerd + runc shim, ctr | container runtime, and its client, which runs workloads | static Go, no libc |
| runc | OCI runtime | static PIE (cgo: musl, libseccomp; C with LTO) |
| CA certificates | registry TLS | — |
| serviced | PID 1: runs the services, confines them, keeps their logs, handles power | static PIE (musl, libunwind; Rust LTO) |
| network-controller, machine-controller, storage-controller, time-controller, trust-controller, workload-controller, machine-apiproxy | the services of the image: DHCP, instance setup and the machine's API, `/var`, time, the TPM, workloads, the API over mTLS ([Services](#services)) | static PIE (musl, libunwind; Rust LTO) |
| cryptsetup | formats and opens the encrypted state partition (LUKS2), run by storage-controller | static (musl, OpenSSL's libcrypto, json-c, libdevmapper, popt, libuuid; LTO) |
| mke2fs | creates the filesystem of the encrypted state partition, run by storage-controller | static (musl, e2fsprogs' libraries; LTO) |

The `kubernetes-1-37` image adds kubelet, kubelet-controller, the pod sandbox image (`pause`),
the CNI plugins, `mount` and the netfilter tools ([its contents](kubernetes-target.md#contents)).

Everything is compiled by clang (LLVM), linked by lld, against musl and compiler-rt (no GCC,
glibc or libgcc), and every program is statically linked: the image has no dynamic loader and no
shared library. What ships is built with ThinLTO: musl (but its start files, its dynamic linker's
entry and mimalloc), libunwind, libseccomp, runc's C code, pause, cryptsetup, mke2fs and the
libraries linked into them (`-flto=thin`), the Rust binaries (their workspaces' release profile,
`lto = "thin"`) and the kernel (`CONFIG_LTO_CLANG_THIN`); Go has no LTO. musl's allocator is
mimalloc 3 in its hardened mode (`MI_SECURE`), built into musl (patches and glue in
[`specs/targets/tools/components/musl`](../specs/targets/tools/components/musl), after Chimera
Linux's mimalloc 2 integration). The build tools link musl dynamically.

The image has no shell, no coreutils, no package manager, no systemd (only its EFI stub) and no
interpreters. `/etc` lives on the read-only root; the files that change at runtime are symlinks
into `/run/hardened`.

## Boot

1. **UEFI** loads `/EFI/BOOT/BOOTX64.EFI` from the ESP: the UKI, signed with the Secure Boot key.
2. **systemd-stub** measures the UKI sections (kernel, command line, os-release) into PCR 11 and
   starts the kernel. There is no initrd.
3. **The kernel** sets up the root device from its command line with dm-init:

   ```text
   dm-mod.create="root,,,ro,0 <sectors> verity 1 PARTUUID=<data> PARTUUID=<hash> 4096 4096
                  <blocks> 0 sha256 <roothash> <salt> 1 restart_on_corruption"
   root=/dev/dm-0 rootfstype=erofs ro init=/usr/bin/serviced
   ```

   `dm-mod.waitfor` makes it wait for late-probing disks (NVMe). A corrupted block reboots the
   machine.
4. **serviced** (PID 1) mounts `/proc` (`hidepid=invisible`), `/sys`, `/dev`, `/dev/pts`,
   `/dev/shm`, `/run`, `/tmp`, cgroup2, securityfs and bpffs, pins kernel files to the root
   filesystem (LoadPin: the first file the kernel loads is one of the verity root's), applies the
   hardened sysctls, installs the SIGCHLD reaper and power handling (signals, the ACPI power
   button) and serves [its API](#apis). It then creates the sockets of the
   [services](#services) and starts them, each once those it requires are ready, the
   socket-activated ones on their first connection:

   ```text
   network-controller        DHCPv4 on every physical NIC (IPv6 uses kernel SLAAC), resolv.conf
   └─ machine-controller     the platform (DMI, or hardened.platform=), metadata and user-data;
      │                      hostname, sysctls, kernel modules, containerd's configuration; then
      │                      configures, in order:
      ├─ network-controller     the DNS override
      ├─ storage-controller     /var: the state partition grown, unlocked with a key
      │                         trust-controller unseals (or formatted) when encrypted, mounted
      ├─ time-controller        the NTP servers
      ├─ workload-controller    user-data's workloads
      ├─ kubelet-controller     kubelet's files, and kubelet enabled (Kubernetes targets)
      └─ machine-apiproxy       when user-data enables the API
   containerd                once machine-controller and storage-controller are ready
   ├─ workload-<name>        one per user-data or API workload
   └─ kubelet                when user-data enables it (beside workloads)
   ```

   machine-controller is ready once the controllers are configured and it serves the machine's
   API; it configures machine-apiproxy afterwards. serviced logs `boot complete` once every
   enabled service has settled (ready, exited, failed, inactive or stopped).
5. **Shutdown:** a power request comes from serviced's API (the machine API's `Reboot` and
   `Shutdown`), a signal or the ACPI power button. serviced stops the running services, those
   requiring others first (each with SIGTERM, then SIGKILL after 10 s), then kills
   every remaining process (containers: SIGTERM, then SIGKILL after 20 s). Only then does it run
   the `exec-stop` commands of the services that ran, one at a time, the last started first:
   storage-controller's, which unmounts `/var` and closes the encrypted partition, comes after
   everything that used `/var` is gone. Then it calls `reboot(2)`.

A service that fails is restarted with backoff (1 s to 60 s), as its file says; services requiring
it wait. If serviced itself fails (an error or a panic), it logs why and reboots 30 seconds later.

## Services

serviced only runs processes, and knows no service by name. What it runs is services: TOML files
([`libserviced::definition`](../serviced/libserviced/src/definition)) in three layers merged by
name: the image's (`/usr/lib/serviced/services`), the runtime one (`/run/serviced/services`) and
the persistent one (`/var/lib/serviced/services`). [services.md](services.md) documents the
format, the layers, and each service the images ship and why it is configured as it is.

**Supervision.** serviced reads the layers at boot, when a service calls `Reload` (after writing
or removing files in the runtime or persistent layer, whose directories it writes itself), and
whenever a service gets ready or ends (storage-controller mounting `/var` brings the persistent
layer), and reconciles: new and enabled services start, removed and disabled ones stop, changed
ones restart. Each read creates the sockets of the enabled services whose
condition holds, and removes the others', before any service starts: a caller finds no socket
rather than one never answered when the service cannot run.

**Sockets and readiness.** Every service's API is gRPC on a unix socket that serviced creates and
passes to it as systemd does; serviced never accepts on them, so a socket-activated service
(storage-controller, trust-controller, workload-controller, machine-apiproxy) starts on its first
connection. Each service authorizes its own callers: serviced's `IdentifyProcess` tells which
service the peer's pid (`SO_PEERCRED`) belongs to, by its cgroup, and the connection is dropped
unless the socket's `allow` names that service. A `notify` service is ready once it sent
`READY=1` (systemd's protocol), others once started
([details](services.md#sockets-and-activation)).

**Sandboxes.** The services parsing untrusted input run confined, as their file says: their own
namespaces but the network's, a read-only root holding only their programs and binds, their uid
and capabilities, a seccomp allowlist and a cgroup with limits, set up by serviced between `fork`
and `exec` ([details](services.md#sandbox)).

| Service | Does | Confined |
| --- | --- | --- |
| network-controller | DHCP and lease renewal, `resolv.conf` | yes |
| machine-controller | instance setup, the controllers' configuration, the machine's API ([APIs](#apis)) | no: it loads modules, sets sysctls and the hostname |
| storage-controller | `/var` ([disk layout](#disk-layout)); socket-activated | no: it mounts and opens dm-crypt devices |
| time-controller | [time](#time) | yes |
| trust-controller | the TPM: [attestation](#attestation) and sealing; socket-activated, with a TPM only | yes |
| workload-controller | the `workload-<name>` services ([workloads](#workloads)); socket-activated | yes |
| kubelet-controller | kubelet's configuration ([Kubernetes](#kubernetes)) | no: it writes kubelet's files |
| machine-apiproxy | the machine's API over mTLS ([APIs](#apis)); socket-activated, when enabled | yes |
| containerd | the container runtime | no |
| kubelet | the Kubernetes node agent | no |
| workload-&lt;name&gt; | a [workload](#workloads) | no (the container is confined by runc) |

What each one's confinement allows and why: [services.md](services.md#the-services).

## Controllers

Each controller owns a domain: network-controller the network and `resolv.conf`,
storage-controller `/var`, time-controller the clock, trust-controller the TPM,
workload-controller the workloads, kubelet-controller kubelet's configuration. machine-controller
alone reads metadata and user-data, and gives each controller its part through its API's
`Configure` (configured in the order of [Boot](#boot)).

- **Typed APIs.** User-data, with Bottlerocket's keys and value formats for the settings
  Bottlerocket has, is parsed into validated domain types; each controller's part travels as a
  typed protobuf message (`hardened.<domain>.v1`), which the controller converts back into those
  types, validating it as user-data parsing does. No API carries JSON or TOML strings. Each
  controller is also a library with its API (its `proto/` directory, the generated client and
  server, its socket) and its part of the settings, with their conversions; machine-controller's
  has the settings' root and user-data parsing, and
  [`controllers/controllers-helpers`](../controllers/controllers-helpers) the values several of
  them share.
- **Failures.** network-controller and storage-controller are essential: if one cannot be
  configured, machine-controller fails, and serviced restarts it. The others' failures are logged
  and the machine boots without them (no time synchronization, no workloads, no kubelet, no API).
- **Restarts.** A controller keeps what it was configured with, and what it did, in
  `/run/<controller>/state.json`, and reapplies it when it restarts, without being configured
  again: network-controller its DNS override (DHCP runs again), storage-controller what backs
  `/var` (it adopts a `/var` already mounted), time-controller its servers (it polls them again
  at once), workload-controller user-data's workloads, kubelet-controller kubelet's files,
  machine-apiproxy its configuration. machine-controller keeps the machine's identity and
  user-data as fetched, so a restart neither fetches metadata again nor reconfigures the
  controllers. `/run` is a tmpfs: a reboot starts over.

## APIs

```text
hctl ──mTLS──▶ machine-apiproxy ──▶ machine-controller ─┬─ Machine ──▶ serviced,
                                                         │   storage-controller, time-controller
                                                         ├─ Workloads ──▶ workload-controller
                                                         │                  └─▶ serviced
                                                         └─ Attestation ──▶ trust-controller
                                                                              └─▶ /dev/tpmrm0
```

- **serviced's API** (`hardened.serviced.v1`,
  [`serviced.proto`](../serviced/libserviced/proto/hardened/serviced/v1/serviced.proto)) on
  `/run/serviced/serviced.sock`: the services (their merged definitions and states; start, stop,
  restart, reload), the services' logs and serviced's own, reboot and power off. Services write
  the files of the runtime and persistent layers in their directories, then reload. serviced
  knows its callers by their cgroup and allows what their file's `api` grants (`read`,
  `control`): machine-controller, workload-controller and kubelet-controller have both.
  `IdentifyProcess` is open to every service.
- **The controllers' APIs** (in each controller's `proto/` directory): `Configure` and their
  state, for machine-controller; trust-controller's `Sealing`, for storage-controller.
- **The machine API**, served by machine-controller to machine-apiproxy alone:
  `Machine` (`hardened.machine.v1`, machine-controller's) from what it knows (version,
  `GetSettings`: a typed `Settings` without secrets) and from the other APIs (`Storage` is
  storage-controller's state, `Time` time-controller's status, `Logs` serviced's own log, `Reboot`
  and `Shutdown` serviced's); `Workloads` (`hardened.workloads.v1`, workload-controller's)
  forwarded to workload-controller, `Attestation` (`hardened.attestation.v1`, trust-controller's)
  to trust-controller.

machine-apiproxy terminates TLS, requires a client certificate from the configured CA, reads the
role from the certificate's Organization (`hardened:reader` or `hardened:admin`), and checks the
gRPC method against the role table in its library: unknown methods, so new ones unless added to
the read-only list, require admin. It forwards the authorized calls unchanged to
machine-controller's socket. machine-controller enables it when user-data sets
`settings.hardened.api`, and configures it.

machine-apiproxy is the only service parsing TLS from the network, so it sees nothing else (its
TLS identity and machine-controller's socket, [its sandbox](services.md#machine-apiproxy)) and
never holds the TPM, which could unseal the state partition's key; its limits keep a flood from
starving the machine. An admin can create privileged workloads, so a compromise of
machine-apiproxy has an admin's power, and nothing else.

## Logs

- **Services:** serviced reads each process's standard output and error. Every line goes to the
  service's log file, `/var/log/serviced/<service>.log` once storage-controller mounted `/var` and
  created that directory, `/run/serviced/logs/<service>.log` for a run started before (rotated
  past 32 MiB); to the service's log in memory, which serviced's `Logs` serves (a log starts with
  the last lines of its file, so with the previous boots' for the services logging on `/var`); and
  to the console for `console = true` services. When another service fails, the last 20 lines of
  its run are copied to serviced's log, for its first three failures.
- **serviced:** on the console, as `[   12.345678] serviced: message key=value` to read as one log
  with the kernel's, and in memory (5000 lines), served by its `Logs` and the machine's
  `Machine/Logs` (`hctl logs`).
- **The console** is best effort: a thread of serviced writes it, and when the serial console
  falls behind, lines are dropped, then counted (`N console lines dropped`). The log files and
  the logs in memory are the record.
- **Workloads:** a container's output is its service's (`hctl workloads logs <name>`, through
  workload-controller).

## Filesystem layout

The root is read-only. What changes is in `/run`, a tmpfs started over at every boot, and `/var`,
the state partition ([disk layout](#disk-layout)):

```text
/run
├── hardened/            resolv.conf (network-controller), hostname and hosts (machine-controller),
│                        which /etc's links point to
├── serviced/            serviced.sock, its API; services/, the runtime layer; notify/<service>,
│                        the notify sockets; logs/, the logs of runs started before /var;
│                        sandbox/<service>/, the sandboxes' roots
├── <controller>/        each controller's runtime directory: api.sock, state.json
├── containerd/          config.toml and certs.d/ (machine-controller); containerd's socket, state
├── kubelet/             kubelet's configuration and credentials (kubelet-controller)
└── cni/net.d/           the CNI configuration (/etc/cni/net.d links here)

/var
├── lib/serviced/services/   the persistent layer: the API's workloads
├── log/serviced/            the services' logs
├── lib/containerd/          images, snapshots, containers
├── lib/kubelet/             kubelet's state: its rotated certificate, the static pods' manifests
├── lib/cni/bin/             network add-ons' CNI plugins (/opt/cni/bin links here)
└── ...                      the workloads' bind mount sources
```

## Disk layout

```text
GPT
├── 1  esp                 64 MiB FAT32     EFI/BOOT/BOOTX64.EFI
├── 2  root-x86-64         erofs (lz4hc)    read-only, GPT flag 60
├── 3  root-x86-64-verity  dm-verity tree   read-only, GPT flag 60
└── 4  var                 ext4 (64 MiB)    grown by storage-controller to the end of the disk;
                                            LUKS2 with ext4 inside when encrypted
```

The partition UUIDs of the root and its hash tree are the two halves of the root hash, as with
systemd-repart. The other UUIDs, the verity salt and the filesystem UUID are derived from the
root filesystem manifest, so identical inputs give an identical image.

The image ships an empty 64 MiB ext4 state partition, formatted at build time, so an unencrypted
`/var` needs no mkfs, fsck or resize tools. When the disk has grown since the GPT was written (its
backup header is no longer on the last sector), storage-controller moves the end of partition 4
to the end of the disk (on a MiB boundary), replaces the GUID it has in the image (the same on every
machine, derived from the root partition's) by a random one, kept on later resizes, rewrites the
GPT and tells the kernel with `BLKPG_RESIZE_PARTITION` (the root disk is busy, so the table can't
be re-read). On every boot it then grows the mounted filesystem online (`EXT4_IOC_RESIZE_FS`, a
no-op when it already fills the partition), so a resized volume is picked up on the next boot.

There is no fsck: the ext4 journal makes unclean shutdowns safe, metadata checksums detect
corruption, and `/var` is mounted `errors=remount-ro`. If the partition is missing or does not
mount, `/var` is a tmpfs, nothing persists and storage-controller logs a warning.

**Encryption** (`settings.hardened.storage.encryption = "tpm"`, off by default) makes partition 4
a LUKS2 volume whose key is sealed to the TPM and the booted image (PCR 11); a key that cannot be
unsealed means a new, empty partition, and a failure a tmpfs `/var`, never an unencrypted one
([state-encryption.md](state-encryption.md)). `hctl storage` shows what backs `/var`, and why.

## Workloads

A workload is a service, `workload-<name>`
([`service_file.rs`](../controllers/workload-controller/src/service_file.rs)), which
workload-controller writes in serviced's layers, then reloads serviced: user-data's in the runtime
layer, at every boot (machine-controller's `Configure`), the API's in the persistent layer, kept
across reboots. The workload itself is kept in the service's `meta.workload`, which `Workloads/List`
reads back. No Rust code talks to containerd.

- **Namespace:** workloads are in containerd's `system` namespace, Kubernetes' pods in CRI's,
  `k8s.io`: both run on a Kubernetes node.
- **Images** are pulled by the service's `exec-pre`, `ctr images pull --local --sync-fs
  --skip-metadata --hosts-dir /run/containerd/certs.d`, with the registry mirrors and basic
  credentials machine-controller writes there
  ([user-data.md](user-data.md#settingscontainer-registry)). ctr unpacks the layers itself and syncs them to disk (containerd's transfer service would not),
  so a power loss right after a pull cannot leave a corrupted image; it fetches only this
  platform's manifests, as registries rate-limit requests.
- **Running:** the service's `exec` is `ctr run --rm` in the foreground, in the `system`
  namespace: serviced supervises it like any process. The container's exit code is the service's,
  which drives `restart`; SIGTERM, stopping the service, is forwarded to the container. Its
  command replaces the image's entrypoint and command (ctr cannot keep one while replacing the
  other, so `args` need a `command`). Bind mount sources are created as the service's runtime
  directories.
- **Confinement:** unprivileged containers run with runc's defaults: containerd's default seccomp
  profile, `no_new_privileges` and the default capability set.
- **Networking:** containers share the host network namespace (kubelet's pods use CNI, see below).
- **System images** are "from scratch" images holding a single static binary, today only `pause`
  ([Adding a component](#adding-a-component)). image-builder archives each as a reproducible OCI
  image in `/usr/share/hardened/images/`; kubelet's service imports `pause` into containerd before
  it starts.

## Kubernetes

kubelet's service is disabled in the `kubernetes-1-37` image. kubelet-controller, configured by
machine-controller, writes kubelet's files and enables it with a drop-in in the runtime layer when
user-data sets [`settings.kubernetes`](user-data.md#settingskubernetes). kubelet runs on the host,
unconfined; its pods are in containerd's `k8s.io` namespace, beside the workloads in `system`.
How a node runs, its networking and versions: [kubernetes-target.md](kubernetes-target.md).

## Time

The clock starts from the hypervisor's (kvm-clock, the RTC). time-controller keeps it in sync with
NTP servers, in the background, and is ready once the clock is synchronized, or 30 s after being
configured without. Nothing waits for it.

- **Servers:** `settings.ntp.time-servers`, else those of DHCP (option 42, every interface's,
  the primary's first), else `pool.ntp.org`; chosen once per boot, by machine-controller, which
  configures time-controller with them. Until then, time-controller does not poll.
- **Protocol:** SNTP (RFC 4330). Every poll interval (32 s to 2048 s, longer while the clock stays
  close), time-controller queries every address of every server and keeps the reply with the
  smallest synchronization distance; replies must echo the request's random cookie, and
  unsynchronized servers are ignored.
- **Corrections:** an offset of 0.4 s or more steps the clock; a smaller one goes to the kernel's
  PLL, which slews the clock and learns its frequency error, so time never jumps once in sync. The
  kernel then copies the clock to the RTC every 11 minutes.
- **API:** `Machine/Time` (`hctl time`) returns time-controller's status
  (`hardened.time.v1.Status`): whether the kernel considers the clock synchronized, its error
  bounds and frequency correction, the servers and where they come from, and its last correction
  since it started (server, stratum, offset, round trip) or why the last round made none.

It runs sandboxed with `CAP_SYS_TIME` only ([services.md](services.md#time-controller)), which
gives a compromised time-controller nothing beyond what anyone answering its unauthenticated
queries can do: set the clock.

## Attestation

With a TPM present (a vTPM on cloud VMs), trust-controller, socket-activated and run only when
`/dev/tpmrm0` exists, is its only user. It serves attestation evidence
(`hardened.attestation.v1.Attestation`) to machine-controller, which forwards the API's calls:

- **PCR values** from the SHA-1, SHA-256 and SHA-384 banks.
- **The TCG event log** written by the firmware and systemd-stub, read from securityfs.
- **Quotes** (`TPM2_Quote`) over a verifier-supplied nonce, signed by a restricted ECDSA P-256
  attestation key. The key is a primary key under the endorsement hierarchy, so it is the same
  across reboots without being stored anywhere. trust-controller checks that the quote's PCR
  digest matches the PCR values it returns.

It also seals and unseals secrets to the booted image (`hardened.trust.v1.Sealing`) for
storage-controller: the key of the encrypted state partition
([state-encryption.md](state-encryption.md)). Each of its APIs has one client, checked on every
call. It runs as root without any capability, seeing only the TPM device and securityfs. Its TPM
client is its own ([`controllers/trust-controller`](../controllers/trust-controller), `tpm.rs`).

Since the UKI command line (and therefore the verity root hash) is measured, a verifier can
check the exact OS image a machine booted.

## Build system

`cargo builder` runs on the host and runs every step needing tools in a container of the
component's build environment.

### Pipeline

The build's specifications are in [`specs/`](../specs/): a pipeline of **targets** (`targets/`,
[`targets.rs`](../image-builder/src/targets.rs),
[`pipeline.rs`](../image-builder/src/pipeline.rs)), each with the recipes of its
components, from a **seed** (the pinned StageX images of `bootstrap`'s `[seed]`, from which
image-builder generates a Containerfile) to the image. Like the stages of a Dockerfile, each
target builds on one other, its `environment`, and its image is that environment's image with its
own components' trees:

```text
bootstrap  FROM the StageX seed  static toolset under /cross: LLVM (clang, lld, compiler-rt),
                                 BusyBox, make, CMake, Python; Go; the kernel's UAPI headers
tools      FROM bootstrap        what the images' components build with: compiler-rt, musl,
                                 libc++, the userland, LLVM, interpreters, build systems,
                                 libraries, Rust
image-tools                      what assembles the images (mkfs.erofs, veritysetup, mke2fs,
  FROM tools                     systemd-stub, qemu-img) and boots them (qemu, OVMF, swtpm)
standard   FROM tools            the image: base-files, kernel, runc, containerd, serviced,
                                 system-controllers...
kubernetes-1-37                  standard's components, then pause, mount, iptables, nft, the
  FROM tools, extends standard   CNI plugins, kubelet and kubelet-controller
```

A target's `components` build on its environment's image (bootstrap's, on the seed), each with
the trees of the target's components its recipe `depends-on`, transitively. A component rebuilds
only when what it builds with changes. In `tools`, the toolchain is spelled out: musl depends on
compiler-rt, the userland on the target libraries, LLVM on all of them, and everything else on
`llvm`. A dependency the environment already has is satisfied as is: standard's recipes list what
they use of `tools` (the kernel's bison, perl or pahole...) as documentation.

A recipe several targets build is in `specs/components/`; a target's file of the same name
overrides it, merged over it: tables merge key by key (metadata, `[vars]`, `[sources]`...), any
other value replaces (`depends-on`, the `[[build]]` steps as a whole). Recipes put what a target
may change in `[vars]`: bootstrap's make, CMake, Python and LLVM override only `prefix`
(`/cross`) and their flags, to be built static on the seed alone. A component built by several
targets has the same cache key in each when its recipe and environment are the same. `extends`
starts a target from another: its components come first, built from the same recipes (a target's
own, then those of the targets it extends, nearest first, then the shared ones), and
`kernel-cmdline` adds to its own.

StageX's tools are linked dynamically against a musl at the very paths of ours (`/lib/ld-musl-
x86_64.so.1`, `/usr/lib/libc.so`), so StageX never reaches a later environment: `bootstrap`
builds a static toolset under `/cross` with it, and everything else builds from that on an
empty root (`PATH` ends with `/cross/llvm/bin:/cross/bin`; busybox also gives `/bin/sh` until
bash replaces it). The bootstrap clang targets `x86_64-hardened-linux-musl`, with compiler-rt,
LLVM's libunwind and libc++ and lld as defaults; `tools` builds the target libraries with it,
then the userland and LLVM natively against them. From then on the system compiles with our
clang (`cc`), the binary tools are LLVM's under their GNU names (`ld` is lld), and clang compiles
with `-fstack-protector-strong` everywhere (its configuration file).

An exported target (`[export]`) is an image: `cargo builder image|run|test --target <name>`
(default `standard`) builds it and only what it needs. The image of its `export.environment`
(`image-tools`) assembles it (mkfs.erofs, veritysetup, mke2fs, qemu-img, systemd-stub's stub, ukify
and systemd-sbsign) and boots it for `run` and `test` (qemu, OVMF and swtpm, all built from
source). That target builds on `tools` beside the images, which build on `tools` alone: changing a
tool that only assembles or boots them rebuilds none of their components. `kernel-cmdline` and
`[partition]` sizes are its own.

`cargo builder plan <target>/<component>` (or just `<component>` when one target lists it)
prints a component's environment and plan. Each distinct environment is an image built from a
generated Containerfile (in `build/environments/`) copying the components' trees, keyed by the
seed and its components' cache keys. Components build in parallel (`--parallel`, 4 by default)
as soon as what they need is built; their output goes to `build/logs/<target>/<component>.log`.

Go is built from source with StageX's Go (in `bootstrap`); it is static, so it runs anywhere.
Rust is built against our LLVM (`llvm-config`), bootstrapped from the pinned release binaries
for musl its source names (stage0), as upstream does; the toolchain links with clang and lld,
dynamically against musl (`crt-static = false`), and builds the image's programs as static PIEs
(`+crt-static` with `--target`). The kernel builds with `LLVM=1`.

### Recipes

A recipe declares metadata and pinned sources, and describes its build as a plan: a list of
steps (run a command, install, copy, write...) on locations such as `work:`, `root:/` (the
component's tree), `out:` or `dep(<target>/<component>):`. Recipes never run anything themselves:
image-builder executes the steps, commands in a container of the component's environment through
`podman exec` with their arguments passed as they are (no shell script, no quoting), file steps
on the mounted directories.

A component installs one tree, at `/`: in the image when its target is exported, in the
environments holding its target otherwise. Every tree keeps the merged-`/usr` layout.

1. **Load:** load the targets, merge their overrides, describe every recipe's plan, and check the
   references: a misused build API (writing to another component's output or a read-only
   location, an undeclared image, a pattern in a command, an invalid environment variable), an
   unknown component, or an output nobody writes fails here.
2. **Fetch:** download sources and verify their SHA-256, into a cache named by checksum
   (`build/cache/sources/<sha256>`).
3. **Build:** each plan runs in its own container with `--network=none`. Only a recipe's fetch phase
   (the Rust components' `cargo fetch --locked`, in each Cargo workspace they build) gets network
   access, and it is verified by the workspace's `Cargo.lock`. Go dependencies are vendored
   upstream. Outputs are cached under `build/components/<name>/`, by key. The key hashes the plan,
   the source checksums, in-tree sources, the environment key and the keys of the component's
   dependencies, so refactoring a recipe without changing its steps rebuilds nothing.
4. **Assemble:** merge the trees of the exported target's components. A path owned by two
   components is an error. The build fails on setuid/setgid or world-writable files, and on any
   ELF file that is not a static executable or a kernel module (an interpreter, `DT_NEEDED`
   libraries, or a shared library). Then every executable that still has a symbol table or debug
   information is stripped (`llvm-strip --strip-all`, from the environment; deterministic), once
   for all components, whatever their builds did; kernel modules are left alone, their signature
   covers them. The manifest records the stripped files.
5. **Seal:** `mkfs.erofs` with fixed timestamps and all files owned by root, then `veritysetup
   format`.
6. **UKI:** ukify (from the systemd source tree) with the kernel, the command line and
   os-release, signed with `systemd-sbsign`. A development key is generated in `build/keys/` if
   none is present.
7. **Disk:** ESP (FAT32 written in Rust, fixed timestamps), GPT, protective MBR, then qcow2.
8. **SBOM:** CycloneDX 1.6. It has one component per component built for the target, with
   source URLs and checksums, license, purl and CPE. Under each sit the Go modules (`go version
   -m`), Rust crates (`cargo tree`) and standard libraries linked into its binaries. The metadata
   records the qcow2 checksum, root hash, kernel command line and the pinned images of the seeds
   the build bootstraps from. The build tools are components too, so they are listed with their
   sources.

### Adding a component

A new component is a recipe in its target's `components/`, starting from a similar one
(`ca-certificates` installs a file, `pcre2` is autotools, `kmod` Meson, `json-c` CMake,
`containerd` Go); [`declarative.rs`](../image-builder/src/recipe/declarative.rs) documents
the format. It lists in `depends-on` what it builds with among its target's components (its
environment's are always there), and is listed in a target. Its build is a list of steps of fixed
kinds (`configure`, `cmake`, `meson`, `run`, `make`, `install`, `go-build`...), calls of the
build API below, which install into the component's tree, `{dest}`. Strings only substitute values
(`{version}`, `{vars.x}`, `{llvm.target}`), locations (`{src}`, `{dest}/usr/bin`, `{work:x}`) and
`{jobs}`: no conditionals or loops. A program the image runs comes with its
[service](#services) file, which its recipe writes to `{dest}/usr/lib/serviced/services`, and a
section in [services.md](services.md); a test of `libserviced` checks the image's service files.

Recipes share values through `[exports]` (`{llvm.target}`, `{compiler-rt.resource-dir}`,
`{python.site-packages}`) and sources (`from = "llvm"`); a list item that is exactly the
reference of a list is replaced by its items. An output is written to `{out:<name>}`; another
component's tree is read from `{dep:<target>/<component>}` and its output from
`{dep:<target>/<component>/<output>}`, which are the dependency declarations. Image assembly
reads the kernel's and systemd-stub's outputs the same way. A container image ("from scratch",
see `pause`) is declared in `[images.<name>]` and filled through `{image:<name>}`; it is
`localhost/hardened/<name>:<version>`.

The build API is in [`recipe/plan.rs`](../image-builder/src/recipe/plan.rs), the executor
in [`exec.rs`](../image-builder/src/exec.rs). The rules:

- **Locations:** steps write only to the component's own places (`work:`, `{dest}`, `out:`,
  `sbom:`, its declared images); sources, the repository and dependencies are read-only.
  `install`, `copy` and `remove` accept patterns (`*`, `?`, `**`), resolved when they run;
  commands never do.
- **Modes:** `Mode` cannot express setuid, setgid or sticky bits.
- **Kernel configuration:** `kernel-config` starts from `allnoconfig` with the fragment
  (`KCONFIG_ALLCONFIG`): anything not listed there, or selected by what is, is off. It then
  checks that every option made it into `.config` (Kconfig silently drops options whose
  dependencies are unmet).
- **Helpers apply the policy:** `go-build` vendors, uses `-trimpath`, applies full RELRO with
  cgo and records Go modules for the SBOM; `cargo-build` is `--offline --locked` and records the
  crates and toolchain.

`specs/` is laid out like Rust modules: a recipe with data files is a directory,
`<name>/spec.toml` next to them, such as the kernel's `config.fragment`, base-files' `files/` or
musl's patches (an override uses its recipe's); likewise a target is `specs/targets/<name>/
spec.toml` next to its `components/`. Specs use dotted keys (`make.install.dest = "{out:dev}"`),
one per line, rather than inline tables (but `{}`, a step without options).

## Security model, in short

| Threat | Mitigation |
| --- | --- |
| Persistent root compromise | Read-only, dm-verity root whose hash is in the signed UKI; corruption reboots |
| Malicious kernel code | Signed modules only (persistent key in `build/keys/`), and modules and firmware load only from the dm-verity root (LoadPin, pinned at boot), so a leaked key alone loads nothing; no module autoloading; lockdown=integrity; no kexec |
| Escalation through setuid | No setuid binaries (enforced at build time) |
| Bugs in the API | TLS and network handling in an unprivileged sandbox (machine-apiproxy) without the TPM; role checks before forwarding |
| A compromised service reaching others | Each service's API on its own socket, its callers identified by serviced and checked against the socket's allow-list |
| Bugs in other parsers of network input | DHCP, NTP and attestation run in sandboxes, with only the capabilities they need |
| Supply chain | Pinned and checksummed sources, offline builds, SBOM including every linked library |
| Silent configuration drift | Configuration comes only from user-data and the API; unknown keys are rejected |
| Copies of the state disk (snapshots, detached volumes) | Optional LUKS2 encryption of `/var`, its key sealed to the vTPM and the booted image (PCR 11) |

## Known gaps / roadmap

- **Time:** unauthenticated SNTP (no NTS): anyone on the path can shift the clock. The servers are
  chosen at boot (a DHCP renewal changing option 42 is not followed). Leap second announcements
  are ignored: the clock is stepped after one. No PTP (`ptp_kvm`) source.
- **Registries:** kubelet's pulls get their credentials from the CRI plugin's `configs`,
  deprecated in containerd 2 and removed in 2.7, which will need a credential helper instead.
  Workloads' pulls get no identity token.
- **Platforms:** Exoscale only (and qemu).
- **Secure Boot and modules:** UKIs and kernel modules are signed with development keys unless
  `build/keys/` holds release keys (`db.{key,crt}`, `modules.pem`). Enrolling keys in the cloud's
  UEFI variable store is up to the deployment.
- **Attestation:** SEV-SNP and TDX evidence (through configfs-tsm), and the remote-attestation
  management flow (key release).
- **Kubernetes:** an end-to-end test of a node joining a cluster (it needs a control plane in the
  test VM); graceful shutdown per pod (serviced gives every container the same 20 s, ignoring
  `terminationGracePeriodSeconds` and priorities); `/etc/machine-id` (absent: cAdvisor and the
  node's `machineID` read it); a full check of static pod YAML (only its top level is checked);
  kubelet settings Bottlerocket has and hardened not yet (among others `provider-id`,
  `server-tls-bootstrap`, `credential-providers`, `pod-pids-limit`, `container-log-*`, the CPU,
  memory and topology managers, `shutdown-grace-period*`).
- **State encryption:** off by default; bound to plain PCR 11, so an image update formats
  `/var`; no integrity protection, TPM parameter encryption or recovery key
  ([choices](state-encryption.md#choices)).

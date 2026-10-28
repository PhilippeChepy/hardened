# Architecture

## Goals

- **Immutable and verifiable.** Every byte executed on the machine comes from a signed or
  hash-verified artifact. A running machine's root filesystem cannot be changed.
- **Minimal.** The image holds a kernel, a C library, a container runtime and one init/agent
  process. Anything else runs in containers.
- **Accountable.** Everything is built from pinned sources by a reproducible pipeline, and the
  build outputs an SBOM covering everything compiled into the image.

## Image contents

| Component | Why it is there | Linking |
| --- | --- | --- |
| Linux 6.18 (longterm) | the kernel, booted as a UKI: KVM/QEMU guest drivers and what Kubernetes and its CNIs need (BTF included), built in from `allnoconfig` | ThinLTO |
| systemd-stub | UEFI stub of the UKI (only the stub ships) | — |
| containerd + runc shim | container runtime | static Go, no libc |
| runc | OCI runtime | static PIE (cgo: musl, libseccomp; C with LTO) |
| pause | PID 1 of pod sandboxes, shipped inside the bundled sandbox image | static (musl, LTO) |
| CA certificates | registry TLS | — |
| dust-init | init/agent | static PIE (musl, libunwind; Rust LTO) |
| dust-api | mTLS API proxy, a sandboxed process of dust-init | static PIE (musl, libunwind; Rust LTO) |
| dust-ntp | SNTP client, a sandboxed process of dust-init | static PIE (musl, libunwind; Rust LTO) |
| cryptsetup | formats and opens the encrypted state partition (LUKS2), run by dust-init | static (musl, OpenSSL's libcrypto, json-c, libdevmapper, popt, libuuid; LTO) |
| mke2fs | creates the filesystem of the encrypted state partition, run by dust-init | static (musl, e2fsprogs' libraries; LTO) |

The `kubernetes-1-37` image adds (see [Kubernetes](#kubernetes)):

| Component | Why it is there | Linking |
| --- | --- | --- |
| kubelet 1.37 | Kubernetes node agent, run by dust-init | static Go, no libc |
| CNI plugins | `loopback`, `bridge`, `host-local`, `portmap`, run by containerd | static Go, no libc |
| mount, umount | from util-linux: kubelet mounts the tmpfs of secrets and bind mounts with them | static (musl, libmount, libblkid; LTO) |
| iptables-nft, nft | run on the host by CNI plugins (`portmap`, `bridge` with `ipMasq`, add-ons' own) | static (musl, libnftnl, libmnl; LTO) |

Everything is compiled by clang (LLVM), linked by lld, against musl and compiler-rt (no GCC,
glibc or libgcc), and every program is statically linked: the image has no dynamic loader and no
shared library. What ships is built with ThinLTO: musl (but its start files, its
dynamic linker's entry and mimalloc), libunwind, libseccomp, runc's C code, pause, cryptsetup,
mke2fs and the libraries linked into them (`-flto=thin`), the Rust binaries (the workspace's
release profile, `lto = "thin"`) and the kernel (`CONFIG_LTO_CLANG_THIN`); Go has no LTO. musl's allocator is mimalloc 3 in its hardened mode
(`MI_SECURE`), built into musl (patches and glue in [`specs/targets/tools/components/musl`](../specs/targets/tools/components/musl), after
Chimera Linux's mimalloc 2 integration). The build tools link musl dynamically.

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
   root=/dev/dm-0 rootfstype=erofs ro init=/usr/bin/dust-init
   ```

   `dm-mod.waitfor` makes it wait for late-probing disks (e.g. NVMe). A corrupted
   block reboots the machine.
4. **dust-init** (PID 1):
   1. mounts `/proc` (`hidepid=invisible`), `/sys`, `/dev/pts`, `/dev/shm`, `/run`, `/tmp`,
      cgroup2, securityfs and bpffs;
   2. installs the SIGCHLD reaper, power handling (signals, ACPI power button) and the hardened
      sysctl defaults;
   3. detects the platform from DMI, or from `hardened.platform=` on the kernel command line;
   4. runs DHCPv4 on every physical NIC (IPv6 uses kernel SLAAC);
   5. fetches metadata and user-data, then validates the user-data and applies the hostname,
      starts the sandboxed `dust-ntp` (see [Time](#time)), and applies the sysctls and kernel
      modules;
   6. grows the state partition with the disk and mounts it on `/var`, first unlocking it with the
      TPM (or formatting it) when user-data enables its encryption;
   7. starts and supervises containerd (and, when kubelet runs, first makes every mount shared and
      writes kubelet's configuration);
   8. serves the control API on `/run/dust/control.sock` and starts the sandboxed `dust-api`
      (if enabled);
   9. connects to containerd through CRI, retrying every 10 s until it answers, imports the
      bundled system images, then starts the user-data workloads and the API-managed workloads,
      or kubelet instead when user-data enables it;
   10. logs `boot complete`.

   The API does not wait for containerd. If containerd never comes up, the machine stays
   reachable: workload calls answer `unavailable`, while logs (containerd's tail is copied to
   dust-init's log after the first failed attempt), settings, attestation and power calls work.
5. **Shutdown:** a power request comes from the API, a signal or the ACPI power button. dust-init
   then stops dust-api and the workloads (SIGTERM, then SIGKILL after 20 s), or kubelet and every
   pod, stops containerd and dust-ntp, unmounts `/var` and calls `reboot(2)`.

If boot fails, dust-init logs the error and reboots 30 seconds later. A panic in a task is logged
and does not bring PID 1 down.

## Disk layout

```text
GPT
├── 1  esp                 64 MiB FAT32     EFI/BOOT/BOOTX64.EFI
├── 2  root-x86-64         erofs (lz4hc)    read-only, GPT flag 60
├── 3  root-x86-64-verity  dm-verity tree   read-only, GPT flag 60
└── 4  var                 ext4 (64 MiB)    grown by dust-init to the end of the disk;
                                            LUKS2 with ext4 inside when encrypted
```

The partition UUIDs of the root and its hash tree are the two halves of the root hash, as with
systemd-repart. The other UUIDs, the verity salt and the filesystem UUID are derived from the
root filesystem manifest, so identical inputs give an identical image.

The image ships an empty 64 MiB ext4 state partition, formatted at build time, so an unencrypted
`/var` needs no mkfs, fsck or resize tools. When the disk has grown since the GPT was written (its
backup header is no longer on the last sector), dust-init moves the end of partition 4 to the end
of the disk (on a MiB boundary),
replaces the GUID it has in the image (the same on every machine, derived from the root
partition's) by a random one, keeping it on later resizes, rewrites the GPT and tells the
kernel with `BLKPG_RESIZE_PARTITION` (the root disk is busy, so the table can't be re-read). On
every boot it then grows the mounted filesystem online (`EXT4_IOC_RESIZE_FS`, a no-op when it
already fills the partition). A resized volume is therefore picked up on the next boot.

There is no fsck: the ext4 journal makes unclean shutdowns safe, metadata checksums detect
corruption, and `/var` is mounted `errors=remount-ro`. If the partition is missing or does not
mount, `/var` is a tmpfs, nothing persists and dust-init logs a warning.

**Encryption** (`settings.hardened.storage.encryption = "tpm"`, off by default) makes partition 4 a
LUKS2 volume (aes-xts-plain64, 4 KiB sectors) whose key, random, is sealed to the TPM under a PCR 11
policy: only this TPM, booting this image, unseals it. The sealed key is a token of the LUKS2
header. The first encrypted boot formats the partition with the image's static `cryptsetup`, then
creates the filesystem with its static `mke2fs`; later boots unseal the key and open it as
`/dev/mapper/state`, which is mounted on `/var` and grown like the plain one. When the key cannot be
unsealed (a new image, a cleared TPM, another host), the partition is formatted again and the state
is lost; when encryption cannot be set up at all, `/var` is a tmpfs, never an unencrypted
filesystem. What backs `/var`, and why, is in the API (`Machine/Storage`, `hctl storage`). The
reference is [state-encryption.md](state-encryption.md).

## Workloads

dust-init drives workloads through the Kubernetes Container Runtime Interface (CRI), served by
containerd's CRI plugin: the same API kubelet will use. The bindings (`crates/cri-api`) are
generated from the CRI protos vendored by the containerd release that ships in the image.

- **Pods:** each workload is a pod sandbox with one container. The sandbox runs the bundled
  `pause` process (built from Kubernetes' `pause.c`).
- **Images** are pulled through the CRI image service, with the mirrors and credentials of
  `settings.container-registry`: dust-init writes them, before containerd starts, as `hosts.toml`
  files in `/run/containerd/certs.d` (containerd's `config_path`) and in the CRI plugin's
  `configs` of the configuration it generates, `/run/containerd/config.toml` (the image's, plus
  those; generated at every boot, even without registry settings). `configs` is deprecated in
  containerd 2 and removed in 2.7: credentials will then go through a credential helper of stock
  containerd (see the roadmap).
- **System images** are "from scratch" images holding a single static binary; today only
  `pause`. A component declares its image (`b.container_image`) and places files in
  it during its build. dust-builder archives that as a reproducible OCI image and ships it in
  `/usr/share/hardened/images/` on the read-only root. dust-init imports the images into
  containerd at boot. This is the only use of
  containerd's native API left (`crates/containerd-api`).
- **Supervision:** each workload has a task that pulls its image, runs the sandbox and the
  container, waits for exit, cleans up, then restarts according to `restart` with exponential
  backoff.
- **Confinement:** unprivileged containers run with containerd's default seccomp profile
  (`RuntimeDefault`), `no_new_privileges` and the default capability set.
- **Logs** are written by containerd in the kubelet log format under `/var/log/pods/`. dust-init
  decodes them for the API and, with `console = true`, for the serial console.
- **Networking:** pods share the host network namespace (kubelet's pods use CNI, see below).

## Kubernetes

The `kubernetes-1-37` target extends `standard` with kubelet 1.37, the reference CNI plugins,
static `mount` and `umount` (kubelet runs them for the tmpfs of secret and projected volumes, and
bind mounts), and `iptables` (its nf_tables variant only) and `nft`, which CNI plugins run. The
Kubernetes release is pinned once, by `standard/pause` (`{pause.kubernetes}`), so the sandbox
image and kubelet come from the same one. dust-init is the same binary: it runs kubelet when the image has `/usr/bin/kubelet`
and user-data enables `settings.kubernetes` ([user-data.md](user-data.md#settingskubernetes)).

- **kubelet** runs on the host, unconfined, supervised like containerd (restarted with backoff,
  its output in `/var/log/kubelet.log`, copied and truncated past 64 MiB). It uses containerd's CRI
  socket, the cgroupfs driver on cgroup v2 (no systemd), webhook authentication and
  authorization, no read-only port. dust-init writes its `KubeletConfiguration`, kubeconfigs and
  bootstrap token to `/run/kubelet` at every boot from user-data (TLS bootstrapping; kubelet
  then rotates its client certificate); kubelet keeps its state in `/var/lib/kubelet`. It starts once containerd has the
  bundled images (the sandbox image is the bundled `pause`, pinned by containerd's configuration).
  Static pods from user-data are written to its `staticPodPath`, `/run/kubelet/manifests`.
- **Pods:** kubelet removes the pods it did not create, so dust-init runs no workload of its own
  then: `settings.hardened.containers` is rejected and the workload API is unavailable.
- **Mounts:** dust-init makes every mount shared (`/` recursively, as systemd does) before
  containerd starts, for mount propagation.
- **CNI:** containerd looks for plugins in `/usr/libexec/cni` (the image's) then `/opt/cni/bin`, a
  link to `/var/lib/cni/bin` where network add-ons install theirs; its configuration directory is
  `/run/cni/net.d`, linked from `/etc/cni/net.d`, where add-ons write it. `iptables` and `nft`
  are in `/usr/bin`, the `PATH` dust-init gives containerd (and so the plugins) and kubelet.
- **Kernel:** the same as `standard`'s, whose configuration covers kube-proxy (nftables and
  iptables-nft modes, IPVS), bridges and overlays, BPF, and the keys kubelet checks.
- **Shutdown:** kubelet's graceful node shutdown relies on systemd, so dust-init stops kubelet, then
  every container and pod sandbox through CRI.

The target's reference is [kubernetes-target.md](kubernetes-target.md).

## API

```text
hctl ──mTLS (h2)──▶ dust-api (sandboxed child of dust-init) ──unix socket──▶ dust-init
```

`dust-api` is a generic, authorizing HTTP/2 reverse proxy. It terminates TLS, requires a client
certificate from the configured CA, reads the role from the certificate's Organization
(`hardened:reader` or `hardened:admin`), and checks the gRPC method against the role table in
`dust-proto`. Unknown methods require admin. Otherwise it forwards the stream unchanged, so new
RPCs need no proxy changes. Keeping TLS parsing and the network-facing code out of PID 1 limits
what a TLS-layer bug can reach, and a crash or a flood only takes the API down.

dust-init runs dust-api itself, not through containerd, so the API does not depend on the
container runtime. It runs in a generic sandbox (`crates/dust-init/src/sandbox.rs`), entered
between `fork` and `exec`; `api.rs` only adds its binds, limits and networking system calls:

- **Namespaces:** its own mount, IPC, UTS and cgroup namespaces; the host network, where it
  listens.
- **Root:** a read-only tmpfs holding only its (static) binary, the control
  socket directory (socket mode 0660, group 65534) and its TLS material, entered with
  `pivot_root`. There is no
  `/proc`, `/sys`, `/dev`, `/etc` or `/var`, and nothing else to execute.
- **Identity:** uid/gid 65534, no supplementary groups, an empty capability bounding set and
  `no_new_privs`.
- **seccomp:** an allowlist (the sandbox's base set plus networking); anything else kills it. `clone` is
  limited to threads; `ioctl`, `prctl` and `socket` to the few uses it has.
- **cgroup** `/sys/fs/cgroup/sandbox/dust-api`: `memory.max` 128 MiB, `pids.max` 128, `cpu.max` half a
  CPU, so a flood cannot starve PID 1 or the workloads.

dust-init forwards its output to its own log and restarts it with exponential backoff.

## Time

The clock starts from the hypervisor's (kvm-clock, the RTC). `dust-ntp` keeps it in sync with
NTP servers, in the background: nothing waits for it.

- **Servers:** `settings.ntp.time-servers`, else those of DHCP (option 42, every interface's,
  the primary's first), else `pool.ntp.org`; chosen once, at boot.
- **Protocol:** SNTP (RFC 4330). Every poll interval, dust-ntp resolves each name (up to 4
  addresses each), queries every address, and keeps the reply with the smallest synchronization
  distance (the server's root distance plus half the round trip). A request carries a random
  cookie as its transmit timestamp, which a reply must echo. It drops replies from unsynchronized
  servers (stratum 16, leap alarm) and ones more than 1.5 s from their reference clock, polls
  less often after a `RATE` kiss-o'-death, and stops querying an address that sends `DENY` or
  `RSTR`.
- **Corrections:** an offset of 0.4 s or more steps the clock (`ADJ_SETOFFSET`); a smaller one goes
  to the kernel's PLL (`ADJ_OFFSET`, with `STA_PLL`), which slews the clock and learns its
  frequency error, so time never jumps once in sync. Each correction clears `STA_UNSYNC`, so the
  kernel copies the clock to the RTC every 11 minutes. The poll interval goes from 32 s up to
  2048 s while the clock stays within 10 ms, and back down past 50 ms or after a step.
- **Sandbox:** the one of dust-api ([API](#api)), with uid/gid 65533 (which the control socket
  does not admit) and `CAP_SYS_TIME`, kept in its bounding and ambient sets. It sees `/etc` and
  `/run/hardened` (for `resolv.conf` and `hosts`) read-only, and `/run/dust-ntp`, where it writes
  its status, read-write. Its seccomp allowlist adds UDP sockets, the resolver's calls, `rename`
  and `clock_adjtime`; its cgroup caps it at 32 MiB, 4 tasks and a tenth of a CPU.
- **API:** `Machine/Time` (`hctl time`) shows whether the kernel considers the clock synchronized,
  its error bounds and frequency correction, the servers and where they come from, and the last
  correction (server, stratum, offset, round trip) or why the last round made none.

Keeping `CAP_SYS_TIME` gives a compromised dust-ntp nothing beyond what anyone answering its
unauthenticated queries can do: set the clock.

## Attestation

With a TPM present (a vTPM on cloud VMs), dust-init offers:

- **PCR values** from the SHA-1, SHA-256 and SHA-384 banks.
- **The TCG event log** written by the firmware and systemd-stub, read from securityfs.
- **Quotes** (`TPM2_Quote`) over a verifier-supplied nonce, signed by a restricted ECDSA P-256
  attestation key. The key is a primary key under the endorsement hierarchy, so it is the same
  across reboots without being stored anywhere. dust-init checks that the quote's PCR digest matches
  the PCR values it returns.

Since the UKI command line (and therefore the verity root hash) is measured, a verifier can
check the exact OS image a machine booted. SEV-SNP and TDX evidence will come later, through
configfs-tsm.

## Build system

`cargo builder` runs on the host and runs every step needing tools in a container of the
component's build environment.

### Pipeline

The build's specifications are in [`specs/`](../specs/): a recipe per component
(`components/`) and a pipeline of **targets** (`targets/`,
[`targets.rs`](../crates/dust-builder/src/targets.rs),
[`pipeline.rs`](../crates/dust-builder/src/pipeline.rs)), from a **seed** (the pinned StageX
images of `bootstrap`'s `[seed]`, from which dust-builder generates a Containerfile) to the
image:

Like the stages of a Dockerfile, each target builds on one other, its `environment`, and its
image is that environment's image with its own components' trees:

```text
bootstrap  FROM the StageX seed  static toolset under /cross: LLVM (clang, lld, compiler-rt),
                                 BusyBox, make, CMake, Python; Go; the kernel's UAPI headers
tools      FROM bootstrap        compiler-rt, musl, libc++, the userland, LLVM, interpreters,
                                 build systems, libraries, Rust, the image tools and the test VM
                                 (qemu, OVMF, swtpm)
standard   FROM tools            the image: base-files, kernel, runc, containerd, pause, dust...
kubernetes-1-37                  standard's components, then mount, iptables, nft, the CNI
  FROM tools, extends standard   plugins and kubelet
```

A target's `components` build on its environment's image (bootstrap's, on the seed), each with
the trees of the target's components its recipe `depends-on`, and of what those depend on,
dependencies first. Builds run in parallel, each as soon as what it depends on is built, and a
component rebuilds only when what it builds with changes. In `tools`, the toolchain is spelled
out: musl depends on compiler-rt, the userland on the target libraries, LLVM on all of them, and
everything else on `llvm`. A dependency the environment already has is satisfied as is: standard's
recipes list what they use of `tools` (the kernel's bison, perl or pahole...) as documentation,
and a recipe may serve several targets. A component may be listed in several targets; it is then built in each (with the same
cache key when its recipe and environment are the same). A target overrides a component's recipe
with `targets/<target>/components/<component>.toml`, merged over it: tables merge key by key
(metadata, `[vars]`, `[sources]`...), any other value replaces (`depends-on`, the `[[build]]`
steps as a whole). Recipes put what a target may change in `[vars]`: bootstrap's make, CMake,
Python and LLVM override only `prefix` (`/cross`) and their flags, to be built static on the seed
alone. `extends` starts a target from another: its components come first, built from the same
recipes (a target's own, then those of the targets it extends, nearest first, then the shared
ones), and `kernel-cmdline` adds to its own.

StageX's tools are linked dynamically against a musl at the very paths of ours (`/lib/ld-musl-
x86_64.so.1`, `/usr/lib/libc.so`), so StageX never reaches a later environment: `bootstrap`
builds a static toolset under `/cross` with it, and everything else builds from that on an
empty root (`PATH` ends with `/cross/llvm/bin:/cross/bin`; busybox also gives `/bin/sh` until
bash replaces it). The bootstrap clang targets `x86_64-hardened-linux-musl`, with compiler-rt,
LLVM's libunwind and libc++ and lld as defaults; `tools` builds the target libraries with it,
then the userland and LLVM natively against them. From then on the system
compiles with our clang (`cc`), the binary tools are LLVM's under their GNU names (`ld` is
lld), and clang compiles with `-fstack-protector-strong` everywhere (its configuration file).

An exported target (`[export]`) is an image: `cargo builder image|run|test --target <name>`
(default `standard`) builds it and only what it needs. Its environment assembles it (mkfs.erofs,
veritysetup, mke2fs, qemu-img, systemd-stub's stub, ukify and systemd-sbsign) and boots it for
`run` and `test` (qemu, OVMF and swtpm, all built from source). `kernel-cmdline` and
`[partition]` sizes are its own.

`cargo builder plan <target>/<component>` (or just `<component>` when one target lists it)
prints a component's environment and plan. Each distinct environment is an image: a generated
Containerfile (`build/environments/<key>.Containerfile`) copying the components' trees, tagged
by its key: the seed's name and the digest of its Containerfile, and the cache keys of its
components. Component cache keys include it. Components build in parallel (`--parallel`, 4 by
default) as soon as what they need is built; their output goes to
`build/logs/<target>/<component>.log`.

Go is built from source with StageX's Go (in `bootstrap`); it is static, so it runs anywhere.
Rust is built against our LLVM (`llvm-config`), bootstrapped from the pinned release binaries
for musl its source names (stage0), as upstream does; it links with clang and lld, dynamically
against musl (`crt-static = false`, `-C target-feature=-crt-static` for the workspace). The
kernel builds with `LLVM=1`.

### Recipes

Each component is a recipe, `specs/targets/<target>/components/<name>.toml` (in
`specs/components/` when several targets build it), read when dust-builder loads. A
recipe declares metadata and pinned sources, and describes its build through a small API.
Recipes never run anything themselves: the description is a plan, a list of steps (run a
command, install, copy, write...) on locations such as `work:`, `root:/` (the component's tree),
`out:` or `dep(<target>/<component>):`. dust-builder executes the steps itself: commands in a container
of the component's environment through `podman exec`, with their arguments passed as they are
(there is no shell script and no quoting); file steps on the mounted directories.

A component installs one tree, at `/`: in the image when its target is exported, in the
environments holding its target otherwise. Every tree keeps the merged-`/usr` layout.

1. **Load:** load the targets, merge their overrides, describe every recipe's plan, and check the
   references: a misused build API (writing to another component's output or a read-only
   location, an undeclared image, a pattern in a command, an invalid environment variable), an
   unknown component, or an output nobody writes fails here.
2. **Fetch:** download sources and verify their SHA-256, into a cache named by checksum
   (`build/cache/sources/<sha256>`).
3. **Build:** each plan runs in its own container with `--network=none`. Only a recipe's fetch
   phase (dust's `cargo fetch --locked`) gets network access, and it is verified by
   `Cargo.lock`. Go dependencies are vendored upstream. Outputs are cached under
   `build/components/<name>/<key>`. The key hashes the plan, the source checksums, in-tree
   sources, the environment key and the keys of the component's dependencies, so refactoring
   a recipe without changing its steps rebuilds nothing.
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

A new component is a recipe, `specs/targets/<target>/components/<name>.toml`
([`declarative.rs`](../crates/dust-builder/src/recipe/declarative.rs) documents the format),
starting from a similar one: `ca-certificates` installs a file, `pcre2` is autotools, `kmod` is
Meson, `json-c` is CMake, `containerd` is Go. It lists in `depends-on` what it builds with
among its target's components (its environment's are always there). Its sources are extracted (archives, in `work:<source>`) or taken as
they are, each as `{<source>}`, then its build is a list of steps of a fixed set of kinds
(`configure`, `cmake`, `meson`, `run`, `make`, `install`, `symlink`, `go-build`...), each a call
of the build API below; they work in the `src` tree unless given a `dir` (or `src`, `tree`), and
the build systems install into the component's tree, `{dest}` (`make = { install = true }` builds,
then installs). Strings only substitute values (`{version}`, `{vars.x}`, `{llvm.target}`),
locations (`{src}`, `{dest}/usr/bin`, `{work:x}`) and `{jobs}`, with no conditionals or loops.
`cpe = "<vendor>:<product>"` is the usual CPE 2.3 name. Then list it in a target.

Recipes share values through `[exports]` (`{llvm.options}`, `{compiler-rt.resource-dir}`,
`{python.site-packages}`) and sources (`from = "llvm"`); a list item that is exactly the
reference of a list is replaced by its items. An output is written to `{out:<name>}`; another
component's tree is read from `{dep:<target>/<component>}` and its output from
`{dep:<target>/<component>/<output>}`, which are the dependency declarations. Image assembly
reads the kernel's and systemd-stub's outputs the same way. A container image ("from scratch",
see `pause`) is declared in `[images.<name>]` and filled through `{image:<name>}`; it is
`localhost/hardened/<name>:<version>`.

The build API is in [`recipe/plan.rs`](../crates/dust-builder/src/recipe/plan.rs), the executor
in [`exec.rs`](../crates/dust-builder/src/exec.rs). The rules:

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
spec.toml` next to its `components/`. Specs use dotted keys (`make.install = true`), one per
line, rather than inline tables.

## Security model, in short

| Threat | Mitigation |
| --- | --- |
| Persistent root compromise | Read-only, dm-verity root whose hash is in the signed UKI; corruption reboots |
| Malicious kernel code | Signed modules only (persistent key in `build/keys/`), and modules and firmware load only from the dm-verity root (LoadPin, pinned at boot), so a leaked key alone loads nothing; no module autoloading; lockdown=integrity; no kexec |
| Escalation through setuid | No setuid binaries (enforced at build time) |
| Bugs in the API | TLS and network handling in an unprivileged container; role checks before forwarding |
| Bugs in the NTP client | Run in a sandbox, with `CAP_SYS_TIME` only |
| Supply chain | Pinned and checksummed sources, offline builds, SBOM including every linked library |
| Silent configuration drift | Configuration comes only from user-data and the API; unknown keys are rejected |
| Copies of the state disk (snapshots, detached volumes) | Optional LUKS2 encryption of `/var`, its key sealed to the vTPM and the booted image (PCR 11) |

## Known gaps / roadmap

- **Time:** unauthenticated SNTP (no NTS): anyone on the path can shift the clock. The servers are
  chosen at boot (a DHCP renewal changing option 42 is not followed). Leap second announcements
  are ignored: the clock is stepped after one. No PTP (`ptp_kvm`) source.
- **Registries:** credentials go through the CRI plugin's `configs`, deprecated in containerd 2
  and removed in 2.7. The plan for 2.7 is a credential helper with stock containerd (no patch):
  dust-init would give it the credentials of `settings.container-registry`, with the same
  one-entry-per-host lookup.
- **Platforms:** Exoscale only (and qemu).
- **Secure Boot and modules:** UKIs and kernel modules are signed with development keys unless
  `build/keys/` holds release keys (`db.{key,crt}`, `modules.pem`). Only the kernel's build sees
  the module key (a declared secret of its plan).
  Enrolling keys in the cloud's UEFI variable store is up to the deployment.
- **Attestation:** SEV-SNP and TDX evidence, and the remote-attestation management flow
  (key release).
- **Kubernetes:** an end-to-end test of a node joining a cluster (it needs a control plane in the
  test VM); graceful shutdown per pod (dust-init gives every container the same 20 s, ignoring
  `terminationGracePeriodSeconds` and priorities); `/etc/machine-id` (absent: cAdvisor and the
  node's `machineID` read it); a full check of static pod YAML (only its top level is checked);
  Bottlerocket's kubelet settings not supported yet (among others `provider-id`,
  `server-tls-bootstrap`, `credential-providers`, `pod-pids-limit`, `container-log-*`, the CPU,
  memory and topology managers, `shutdown-grace-period*`).
- **State encryption:** off by default. The key is bound to plain PCR 11, so an image update
  formats `/var`; a signed PCR policy (`PolicyAuthorize`, ukify's `.pcrsig`) would keep it across
  images we sign. No integrity protection (dm-integrity), no TPM parameter encryption, no recovery
  key ([state-encryption.md](state-encryption.md)).

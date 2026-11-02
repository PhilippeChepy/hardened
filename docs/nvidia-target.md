# The NVIDIA variant

`kubernetes-1-37-nvidia` is the Kubernetes image with NVIDIA's GPU driver and Kubernetes plugins:

```sh
cargo builder image --target kubernetes-1-37-nvidia   # build/out/hardened-kubernetes-1-37-nvidia-*.qcow2
```

It extends [`kubernetes-1-37`](kubernetes-target.md) and targets data-center GPUs from Turing on
(T4, A10, A100, L4, L40S, H100...), with NVIDIA's production driver branch (R595).

## Contents

| Component | Version | Installed as | Built |
| --- | --- | --- | --- |
| `nvidia-open-gpu-kernel-modules` | 595.112.07 | `/usr/lib/nvidia/<version>/modules/nvidia.ko`, `nvidia-uvm.ko` | from source, with clang and kCFI, signed with the module key |
| `nvidia-driver` | 595.112.07 | `/usr/lib/nvidia/<version>/root` (the driver root), `/usr/lib/firmware/nvidia/<version>` | NVIDIA's prebuilt user space and GSP firmware, glibc for nvidia-smi |
| `nvidia-controller` | the OS's | `/usr/bin/nvidia-controller` | Rust, static |
| `nvidia-persistenced` | 595.112.07 | the driver root's `usr/bin/nvidia-persistenced`, its service | C, against glibc, libtirpc linked in |
| `nvidia-cdi-hook` | 1.20.1 | `/usr/bin/nvidia-cdi-hook`, containerd's CDI drop-in | Go, static (musl) |
| `nvidia-k8s-device-plugin` | 0.20.1 | image `localhost/hardened/nvidia-device-plugin` | Go, against glibc |
| `nvidia-dra-kubelet-plugin` | 0.5.1 | image `localhost/hardened/nvidia-dra-kubelet-plugin` | Go, against glibc |

**The kernel modules** are NVIDIA's open modules, the GitHub source rather than the driver
package's (which ships its core prebuilt with GCC). They build against the image's kernel: its
configuration, `Module.symvers`, keys and randstruct seed. Their core, built outside kbuild, gets
the kernel's control-flow and Spectre flags by hand (kCFI with FineIBT's arity and padding,
retpolines, return thunks, SLS). They build without LTO (`ld.lld`'s relocatable link of
`nvidia-uvm.o` crashes with it). The kernel exports, despite `CONFIG_TRIM_UNUSED_KSYMS`, the
symbols they use (`ksyms-whitelist` of the kernel's recipe): those they leave undefined and those
their conftest checks are exported, found against a kernel exporting everything. A new driver
version may need others: modpost names them.

**The driver's user space** is the only part of an image not built from source: NVIDIA's
compute and utility libraries (CUDA, NVML, OpenCL, the JIT and NVVM compilers, PKCS#11 for
confidential computing), `nvidia-smi`, `nvidia-debugdump` and MPS, from the driver package of
the modules' version (pinned and checked). They are glibc programs and libraries, laid out as a
driver root (`root/usr/lib/x86_64-linux-gnu`, `root/usr/bin`): CDI specs mount them into GPU
containers; the host only runs `nvidia-smi`, for [MIG](#mig-partitioning).
`nvidia-persistenced`, NVIDIA's open source, is built here instead (below).
With the GSP firmware, they are the target's `prebuilt` directories, which the image's static
linking check leaves out.

**glibc** (2.44, built with clang and compiler-rt in the `glibc` target) is for the plugins: they
load NVML, a glibc library. Their container images hold it with them. The driver root holds it
too (`root/usr/lib64`), for `nvidia-smi` and `nvidia-persistenced`: they run with that glibc's
loader (`ld-linux-x86-64.so.2 --library-path ...`), the host having none of its own.

## At boot

nvidia-controller looks for NVIDIA GPUs on the PCI bus (display controllers, vendor `0x10de`).
Without any, it does nothing more. With some, it loads `nvidia` and `nvidia-uvm` (the kernel loads
the GSP firmware), then makes their device nodes, which the driver does not make itself:
`/dev/nvidiactl`, `/dev/nvidia<N>`, `/dev/nvidia-uvm`, `/dev/nvidia-uvm-tools` and MIG's
capabilities, `/dev/nvidia-caps/nvidia-cap<N>` (managing and monitoring MIG for root only, an
instance's access for all, NVIDIA's defaults). Its API (`hardened.nvidia.v1`) gives
machine-controller the GPUs and whether the driver is ready, and partitions them as
machine-controller configures it, before the plugins run.

**nvidia-persistenced** then starts (its service requires nvidia-controller and
`/dev/nvidiactl`: without GPUs, it stays inactive). It keeps the GPUs initialized while no
program has them open: otherwise the driver shuts a GPU down when its last user closes it, and
its next user waits for it to start again, booting its GSP firmware (seconds), and loses what
`nvidia-smi` set on it. It is NVIDIA's source (the tag of the driver's version) built against the
`glibc` target's glibc, with its libtirpc linked in (glibc no longer has Sun RPC), and patched
for serviced: in the foreground, its messages on stderr rather than syslog, its socket and PID
file in `/run/nvidia-persistenced`, and a numeric `--user` (65532), to which it switches before
opening the GPUs, as NVIDIA intends. serviced does not sandbox it: its system calls and NVIDIA's
ioctls have to be traced on a GPU first. Its socket answers `nvidia-smi -pm` on the host; the
plugins' CDI specs do not mount it into containers (they look for it below the driver root).

When kubelet runs (`settings.kubernetes`) and the driver is ready, machine-controller declares
the plugins as workloads, next to user-data's (a workload of user-data with one of their names
takes its place):

- **the device plugin** (`nvidia-device-plugin`), unless
  [`settings.kubelet-device-plugins.nvidia.enabled`](user-data.md#settingskubelet-device-pluginsnvidia)
  is false: it advertises `nvidia.com/gpu` to kubelet;
- **the DRA kubelet plugin** (`nvidia-dra-kubelet-plugin`), with
  [`settings.hardened.nvidia-dra.enabled`](user-data.md#settingshardenednvidia-dra): it publishes
  the node's GPUs as ResourceSlices, with the node's credentials (kubelet's kubeconfig, which
  embeds the cluster CA). The DRA driver's controller and its device classes are cluster-wide:
  the cluster deploys them (NVIDIA's chart without its kubelet plugin). Enabling both plugins
  advertises the GPUs twice.

Both are privileged, with the host's root at `/host` (read-only): they find the driver root
there, and name its host path in the CDI specs they write in `/var/lib/cdi`, which CRI reads
(the variant's containerd drop-in). The specs' hooks (`nvidia-cdi-hook`: the container's linker
cache, the libraries' symbolic links) run on the host, from runc.

## MIG partitioning

With [`device-partitioning-strategy = "mig"`](user-data.md#settingskubelet-device-pluginsnvidia),
nvidia-controller splits each GPU having MIG (A100, H100, H200, B200, B300, RTX PRO 6000
Blackwell...) into instances of one profile, as Bottlerocket's nvidia-migmanager does, with the
same `mig.profile` values:

```toml
[settings.kubelet-device-plugins.nvidia]
device-partitioning-strategy = "mig"

[settings.kubelet-device-plugins.nvidia.mig.profile]
"a100.40gb" = "2g.10gb"   # 3 instances of 2 slices and 10 GB
"h100.80gb" = "7"         # 7 instances: 1g.10gb
```

- **A known model** (found by its PCI device ID) gets as many instances of its key's profile as
  it has room for (`2g.10gb`: 3 on an A100 40 GB), or the number of instances given, which names
  the profile (`7`: `1g.5gb`; `1`: the whole GPU). Without a key, it is a single instance of the
  whole GPU (`7g.40gb`). Unlike Bottlerocket, which takes the whole GPU then, a profile the model
  does not have is an error.
- **Another GPU having MIG** tries the profiles of the models this list does not know, in their
  keys' order, each repeated as its key's memory and the 7 compute slices allow
  (`"x100.96gb" = "2g.24gb"`: 3), until one applies.
- **MIG mode** is enabled with `nvidia-smi -mig 1`; Hopper and later GPUs apply it at once,
  Ampere GPUs once reset: machine-controller then reboots the machine, as Bottlerocket does (the
  mode stays across reboots). `device-partitioning-strategy = "none"` disables it on GPUs having
  it, the same way.
- **Each instance** is a GPU instance with its compute instance (`nvidia-smi mig -cgi ... -C`),
  made at each boot (the GPU loses them when reset). nvidia-controller records them in its
  runtime directory: a restarted nvidia-controller leaves them, and recreates them only for
  another profile.
- **The device plugin** advertises the instances as `nvidia.com/gpu` (its `single` strategy),
  as Bottlerocket's: pods request them as whole GPUs. It does not run when partitioning failed.
  The DRA kubelet plugin publishes them as `mig.nvidia.com` devices (static MIG).

# Services

serviced (PID 1) runs services: TOML files, one per service, named after their file
(`containerd.toml` is the service `containerd`). This page describes their format, then each
service the images ship and why it is configured as it is. Service files carry no comments: this
page explains them.

## Layers

A service's files are merged by name, key by key, from three directories:

| Layer | Directory | Written by |
| --- | --- | --- |
| image | `/usr/lib/serviced/services` | the recipes of the components they run |
| runtime | `/run/serviced/services` | machine-controller enables machine-apiproxy, kubelet-controller enables kubelet, workload-controller writes the user-data workloads |
| persistent | `/var/lib/serviced/services` | workload-controller: the API's workloads |

Keys are kebab-case; an unknown key is an error, and a service with an invalid file is left out.

Services change the runtime and persistent layers themselves, in their directories: writing a
layer's directory is the authority to define services. They write a file atomically, checked
first (merged with its files in the other layers they see), or remove one, with
[`libserviced::definition::write_service_file`](../serviced/libserviced/src/definition/write_service_file.rs),
then call serviced's `Reload`. Neither needs `mkdir`: serviced creates `/run/serviced/services` at
boot, storage-controller `/var/lib/serviced/services` when it sets `/var` up.

## Format

### Running

| Key | Default | Meaning |
| --- | --- | --- |
| `description` | `""` | For humans. |
| `enabled` | `true` | A disabled service does not start; a later layer enables it. |
| `exec` | required | The program, absolute, and its arguments (no NUL byte). |
| `exec-pre` | `[]` | Commands run to completion, in order, before `exec`; the service fails if one fails. |
| `exec-post` | `[]` | Commands run after `exec` exits, whatever the reason. |
| `exec-stop` | `[]` | Commands run once the service's process is gone, when it is stopped. At shutdown, every service's run after every other process is gone, in reverse start order. |
| `restart` | `always` | `always`, `on-failure` or `never`, with backoff. |
| `env` | `{}` | The environment, the only one the program gets. |
| `runtime-directories` | `[]` | Absolute paths, created before the service starts if missing (mode 0755, owned by the sandbox's user, root without one; an existing directory is left as it is) and kept across restarts. |
| `console` | `false` | Copies the program's output to the console, besides its log. |
| `meta` | `{}` | Ignored by serviced: whoever wrote the file keeps its own data there (workload-controller, a workload's spec). |

A command whose program is prefixed with `-` may fail: its failure is ignored, and its output
stays off the console.

Stopping a service sends its process SIGTERM, then SIGKILL after 10 s; each `exec-post` and
`exec-stop` command then has 10 s too.

### Ordering and readiness

| Key | Meaning |
| --- | --- |
| `requires` | Services that must be ready first. If one fails, is disabled or does not exist, this one does not start. |
| `condition.path-exists` | The service is skipped unless the path, absolute, exists. Its sockets are not created: its callers fail at once rather than wait. |
| `notify` | Ready once the service sent `READY=1` on `NOTIFY_SOCKET` (systemd's notify protocol), rather than once started. Every process gets `NOTIFY_SOCKET`; `STATUS=` shows in the service's status. |

### Sockets and activation

Every service's API is gRPC on a unix socket that serviced creates and passes to it.

```toml
[[sockets]]
name = "api"
path = "/run/trust-controller/api.sock"
allow = ["machine-controller", "storage-controller"]
activate = true
```

- `name`: lowercase alphanumerics and `-`; `path`: absolute.
- serviced creates each socket at boot, before starting anything: its directory root's, mode
  0755 (or the service's runtime directory of that path), the socket 0666.
- It passes the sockets with systemd's protocol: fds from 3, `LISTEN_FDS`, `LISTEN_PID`,
  `LISTEN_FDNAMES` (the sockets' `name`s), and per socket `SERVICED_ALLOW_<NAME>` (its name
  upper-cased, `-` as `_`): its `allow` list, comma-separated.
- A service starts at boot, unless one of its sockets has `activate = true`: it then starts on
  the first connection to such a socket, or when a service requiring it starts. Connections made
  before it runs wait in the backlog.
- Authorization is the service's: it identifies each caller's service with serviced's
  `IdentifyProcess` and drops connections from services not in `allow`
  ([`libserviced::authorization`](../serviced/libserviced/src/authorization)).

### serviced's API

`api` grants a service serviced's API (`/run/serviced/serviced.sock`), which knows its callers by
their cgroup:

- `read`: services and logs;
- `control`: starting, stopping and restarting services, reloading the service files, and power.

`Reload` reads the layers again and applies the differences before answering: the sockets of the
enabled services whose condition holds exist then, and those of the others are gone. It answers
which files or services it left out, and why.

`IdentifyProcess` is open to every service.

### Sandbox

Without `[sandbox]`, the program runs as root with every capability, in the host's namespaces, in
the cgroup `/sys/fs/cgroup/services/<service>` (a process's cgroup is how serviced knows its
service). With it ([`sandbox.rs`](../serviced/serviced/src/sandbox.rs), entered between `fork` and
`exec`), it gets:

- its own mount, IPC, UTS and cgroup namespaces, and the host network;
- a read-only tmpfs root (`pivot_root`) holding only its programs and binds: no `/proc`, `/sys`,
  `/dev`, `/etc` or `/var` unless bound;
- its `user`, only its `capabilities`, `no_new_privs`;
- a seccomp allowlist: serviced's base set (memory, threads, files, polling, time), what its
  sockets need (below) and its `syscalls`. `clone` is limited to threads, `ioctl` and `prctl` to
  the few uses programs have, `socket` to its `socket-families`; anything else kills the process;
- the cgroup `/sys/fs/cgroup/sandbox/<service>`, with its `limits`.

| Key | Meaning |
| --- | --- |
| `user` | uid and gid, without supplementary groups. |
| `capabilities` | Capability names without `CAP_`, kept through the `exec`; an unknown one is an error. |
| `socket-families` | The families `socket` may create: `unix`, `inet`, `inet6`, `netlink`, `packet`. |
| `syscalls` | System calls allowed on top of serviced's base set, by x86-64 name (an unknown one is an error). A sandboxed program using another one is killed with SIGSYS. |
| `limits.memory-mib` | `memory.max`, in MiB. |
| `limits.tasks` | `pids.max`: processes and threads. |
| `limits.cpu-millicores` | `cpu.max`, in thousandths of one CPU: 1000 is one CPU. Limits are not 0. |
| `[[sandbox.binds]]` | Host paths, absolute, visible at the same path, read-only, without executables or devices unless `writable`, `exec` or `device`; `optional` ones are left out when missing. Binds must not nest. |

What serviced adds by itself, so service files only list what is specific to them:

| When the service… | It gets |
| --- | --- |
| is sandboxed | serviced's socket, its notify socket (`NOTIFY_SOCKET`), `unix`, `sendto` |
| has `api` access | `unix`, `connect`, `getsockopt`, `shutdown` |
| declares `[[sockets]]` | `unix`, `accept4`, `getsockopt` (`SO_PEERCRED`), `connect`, `recvfrom`, `sendto`, `shutdown` |
| is in a socket's `allow` | that socket, `unix`, `connect`, `getsockopt`, `recvfrom`, `sendto`, `shutdown` |

musl implements `send(2)` and `recv(2)` with `sendto` and `recvfrom`, and `clock_adjtime` on
`CLOCK_REALTIME` with `adjtimex`. tokio's signal handling needs `socketpair`.

## The services

Who starts when, and who configures whom, is in [Boot](architecture.md#boot);
socket-activated services start on their first call.

### network-controller

DHCPv4 on every physical Ethernet interface, and `resolv.conf`. Ready after the first lease, or
once the attempts timed out: machine-controller then fetches metadata. Interfaces are followed by
index: one removed loses its DHCP client and lease, one plugged in (again) gets a new client.

- **Sandbox**: root without capabilities but the network's, so it owns the files it writes in
  `/run`: `NET_ADMIN` configures links, addresses and routes (rtnetlink), `NET_RAW` opens the
  packet sockets DHCP uses before an interface has an address, `NET_BIND_SERVICE` binds UDP port
  68. Families: `inet` (DHCP once leased), `netlink`, `packet`.
- **System calls**: `bind` (the DHCP sockets, and the netlink ones, which join the link
  notifications group through their address), `setsockopt` (`SO_REUSEADDR`, `SO_BROADCAST`,
  `SO_BINDTODEVICE` on the DHCP sockets); `rename` (`resolv.conf` and its state, replaced
  atomically). Netlink traffic uses `sendto` and `recvfrom`, granted with its API. No `ioctl`
  beyond the base set: interface indexes, addresses and MTUs go through netlink, and new links
  and carrier changes come as netlink notifications (`RTNLGRP_LINK`), not polling.
- **Binds**: `/sys` (whether a new link is a physical Ethernet one: its `type` and `device` in
  `/sys/class/net`, which links into `/sys/devices`); `/run/hardened`, where `/etc/resolv.conf`
  links to; its runtime directory, for its state.

### machine-controller

Sets the instance up from the platform's metadata and user-data: hostname and `hosts`, kernel
modules, sysctls, containerd's configuration. Then it configures the controllers through their
APIs, enables the services user-data asks for, and serves the machine's API
(`hardened.machine.v1` and `hardened.services.v1`, with `hardened.workloads.v1` and
`hardened.attestation.v1` forwarded) from
the controllers' and serviced's, to machine-apiproxy. Ready once the controllers are configured
and its API serves.

- **Unconfined**: it loads kernel modules, sets sysctls and the hostname, and writes
  containerd's configuration.

### storage-controller

The state partition on `/var`: grows it with the disk, unlocks it with a key trust-controller
unseals (or formats it) when encrypted, and mounts it (a tmpfs when it cannot). Started by
machine-controller's first call, which configures it; ready once `/var` is set up, with
serviced's directories there (its logs, the persistent layer), so whatever needs `/var` requires
it. Its `exec-stop` unmounts `/var` and closes the encrypted partition, last
of all at shutdown.

- **Unconfined**: it mounts, and opens dm-crypt devices.

### time-controller

SNTP client keeping the clock in sync, with the servers machine-controller gives it (user-data,
DHCP or the default). Ready once configured and the clock is synchronized, or 30 s after being
configured without a correction.

- **Sandbox**: uid 65533 (not machine-apiproxy's) with `SYS_TIME`: a compromise can set the clock,
  which anyone answering its unauthenticated queries can anyway. Families: `inet`, `inet6`.
- **System calls**: `adjtimex` (`clock_adjtime`, through musl); `bind` (its NTP sockets, and
  musl's resolver); `getsockname`, `recvmsg`, `sendmsg`, `setsockopt` (musl's resolver); `rename`
  (its state). Its queries' `connect`, `sendto` and `recvfrom` are among serving gRPC's.
- **Binds**: `/etc` and `/run/hardened`, for `resolv.conf` and `hosts`; its runtime directory.

### trust-controller

The TPM's only user: attestation evidence (`hardened.attestation.v1.Attestation`) for
machine-controller, and sealing (`hardened.trust.v1.Sealing`) for storage-controller's key.
Started on its first call; without a TPM it never runs and its socket does not exist.

- **Sandbox**: root without capabilities: enough for the root-owned TPM device and event log,
  and nothing else is visible. It never parses TLS: machine-apiproxy's calls reach it through
  machine-controller.
- **Binds**: `/dev/tpmrm0` (a device); `/sys/kernel/security`, the TCG event log.

### workload-controller

Runs workloads as `workload-<name>` services (`ctr images pull`, then `ctr run` in the foreground,
in containerd's `system` namespace, beside kubelet's pods when it runs): user-data's in serviced's
runtime layer, the API's in its persistent layer, kept across reboots. Started by
machine-controller's first call, which configures it. It requires storage-controller: the
persistent layer is on `/var`.

- **Sandbox**: root without capabilities. A workload's service runs any image with any privilege,
  so a compromise has that power anyway; it only talks to serviced and workload-console. The
  services it writes run
  unconfined, as root: `ctr` reaches containerd's socket, and containerd reads the registries'
  `hosts.toml` files (mode 0600).
- **System calls**: `rename` (its state and the service files it writes); `unlink` (removing a
  workload's service file).
- **Binds**: its runtime directory; the runtime and persistent layers' directories, writable. It
  does not see the image's layer, so it checks the files it writes against the others only
  (workload services have no file in the image).

### workload-console

Runs processes in running workloads' containers for workload-controller, which forwards the API's
`Workloads/Exec` (`hctl workloads exec`): `ctr tasks exec` on a pseudo-terminal or pipes, killed
when the call ends first. Socket-activated, once containerd is ready; at most 16 processes at once.

- **Unconfined**: `ctr` reaches containerd's socket. It parses nothing from the network:
  workload-controller, confined, checks the requests first.

### machine-apiproxy

The machine's API over mutual TLS. machine-controller enables it when user-data sets
`settings.hardened.api` (serviced then creates its socket), and configures it; the call starts it.
It forwards calls to machine-controller as its clients' roles allow.

- **Sandbox**: uid 65534. It parses TLS from the network: an admin client can create privileged
  workloads, so a compromise has admin power, but it sees nothing else. Its runtime directory
  holds its TLS identity, the private key readable by it only. Families: `inet`, `inet6`.
- **System calls**: `bind`, `listen`, `setsockopt` (`SO_REUSEADDR`), for its TLS listener;
  `rename` (its state).

### containerd

The container runtime: workloads in its `system` namespace, kubelet's pods in `k8s.io`.
machine-controller writes its configuration (registry mirrors and credentials); its state is on
`/var`. It sends `READY=1` once it serves. `PATH` is where CNI plugins, which inherit its
environment, find `iptables` and `nft`.

- **Unconfined**: it runs every container. Stopping it leaves running containers to their shims,
  which serviced stops with the remaining processes at shutdown.

### kubelet-controller (Kubernetes targets)

Writes kubelet's configuration, credentials and static pods from what machine-controller gives
it, then enables kubelet with a drop-in in the runtime layer, or keeps it disabled. Ready once
configured.

- **Unconfined**: it writes kubelet's files in `/run/kubelet` and `/var/lib/kubelet`, and its
  drop-in.

### kubelet (Kubernetes targets)

The Kubernetes node agent, enabled by kubelet-controller. Its `exec-pre` imports the pod sandbox
image from the root filesystem into CRI's namespace, so it is never pulled. Its runtime
directories are its state, where network add-ons install CNI plugins (`/opt/cni/bin` links
there) and write the CNI configuration (`/etc/cni/net.d` links there). It sends `READY=1` once
started; `PATH` is where CNI plugins and kubelet find `mount`, `iptables` and `nft`.

- **Unconfined**: it runs the node's pods. Stopping it leaves their containers, which serviced
  stops with the remaining processes at shutdown.

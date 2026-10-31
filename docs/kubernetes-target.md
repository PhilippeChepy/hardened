# The `kubernetes-1-37` target

An image that runs as a Kubernetes 1.37 node: `standard`, plus kubelet and what it runs on the
host. `cargo builder image --target kubernetes-1-37` builds `build/out/hardened-kubernetes-1-37-*`.

The target is `specs/targets/kubernetes-1-37/` (`extends = "standard"`). kubelet ships a disabled
service, which kubelet-controller enables when user-data sets
[`settings.kubernetes`](user-data.md#settingskubernetes) (Bottlerocket's keys).

## Contents

Besides `standard`'s components:

| Component | Version | In the image | Notes |
| --- | --- | --- | --- |
| `kubelet` | 1.37.1 | `/usr/bin/kubelet`, its service | Static Go, no libc |
| `kubelet-controller` | the OS's | `/usr/bin/kubelet-controller`, its service | Writes kubelet's configuration and enables it; static Rust |
| `pause` | 3.10.2 | `/usr/share/hardened/images/pause.tar`, a containerd drop-in pinning it | The pod sandbox image, from Kubernetes' `pause.c`, static |
| `cni-plugins` | 1.9.1 | `/usr/libexec/cni/{bridge,host-local,loopback,portmap}` | The reference plugins, static Go |
| `iptables` | 1.8.13 | `/usr/bin/xtables-nft-multi`, and `iptables`, `ip6tables`, their `-save`, `-restore` and `-nft` names | nf_tables backend only, extensions built in; fully static |
| `nftables` | 1.1.7 | `/usr/bin/nft` | Without the interactive CLI, with mini-gmp; fully static |
| `util-linux-mount` | 2.42.4 | `/usr/bin/mount`, `/usr/bin/umount` | kubelet mounts the tmpfs of secret and projected volumes, and bind mounts, with them |
| `libmnl`, `libnftnl` | 1.0.5, 1.3.2 | nothing | Static libraries linked into iptables and nft |

The other components are `standard`'s, reused from its cached builds (same recipes and
environment).

## Running a node

kubelet-controller makes every mount shared, `/` recursively, for mount propagation (CSI drivers,
Cilium), when it starts. When `settings.kubernetes` is set:

1. machine-controller sets `net.ipv4.ip_forward = 1` (before `settings.kernel.sysctl`, which can
   override it), then configures kubelet-controller
   ([`hardened.kubelet.v1`](../controllers/kubelet-controller/proto/hardened/kubelet/v1/kubelet.proto))
   with the cluster's settings and the node name;
2. kubelet-controller writes kubelet's configuration to `/run/kubelet`: `config.json`,
   `kubeconfig`, `bootstrap-kubeconfig`, `ca.crt`; and the static pods to
   `/var/lib/kubelet/manifests`, removing those no longer declared (secrets in files of mode 0600,
   in directories of mode 0700);
3. it enables kubelet's service with its arguments (a drop-in in serviced's runtime layer,
   `/run/serviced/services`), and restarts it when its configuration changed.

Without `settings.kubernetes`, kubelet-controller keeps kubelet disabled.

serviced starts kubelet once containerd is ready: kubelet's service first imports the bundled
`pause` image (`ctr images import`), the sandbox image containerd's configuration pins. kubelet is
supervised like any service, its output in `/var/log/serviced/kubelet.log`.

With a `shutdown-grace-period`, kubelet stops the node's pods itself when the node shuts down:
their `terminationGracePeriodSeconds`, preStop hooks and the critical pods last
(`shutdown-grace-period-for-critical-pods`). Its graceful node shutdown takes a delay lock from
logind over D-Bus; kubelet-controller answers as logind, on `/run/kubelet-controller/logind.sock`
(kubelet's `DBUS_SYSTEM_BUS_ADDRESS`), and holds one of serviced's for as long as kubelet holds
its own (the period plus 5 s): serviced announces the shutdown to it, kubelet is sent
`PrepareForShutdown`, stops the pods, then releases its lock, and serviced goes on. With `0s`
(the default, as in Bottlerocket), or past the delay, serviced stops kubelet, then containerd,
then every remaining process, the pods' containers included (SIGTERM, then SIGKILL after 20 s).

`/etc/machine-id`, which cAdvisor and the node's `machineID` read, is derived from the instance
ID by machine-controller: stable for the instance's life, without revealing the ID.

kubelet runs on the host, unconfined. Its configuration:

- the cgroupfs driver on cgroup v2 (there is no systemd), containerd's CRI socket
  (`unix:///run/containerd/containerd.sock`);
- TLS bootstrapping with the bootstrap token, then a rotated client certificate, kept with the rest
  of its state in `/var/lib/kubelet`;
- webhook authentication and authorization, no anonymous access, no read-only port;
- the node name is the machine's hostname; the node address is the one of the default route;
- the reservations, eviction thresholds and image garbage collection of user-data, when set;
- static pods from `/var/lib/kubelet/manifests`, rewritten at every boot from user-data.

Workloads (`settings.hardened.containers` and the API's) run beside kubelet, in containerd's
`system` namespace; the pods are in CRI's, `k8s.io`. Kubernetes does not see the workloads (keep
their resources from the pods with `system-reserved`). Both pull with the same registry mirrors
and basic credentials; identity tokens and image pull secrets only apply to the pods
([user-data.md](user-data.md#settingscontainer-registry)).

## Networking

Pod networking comes from a cluster network add-on, installed as usual. Its CNI plugins go to
`/opt/cni/bin`, its configuration to `/etc/cni/net.d`: both are links into writable places, as the
root is read-only.

| Path | Is | What uses it |
| --- | --- | --- |
| `/usr/libexec/cni` | the image's plugins | containerd, searched first (`bin_dirs`) |
| `/opt/cni/bin` | link to `/var/lib/cni/bin` | network add-ons install their plugins there; containerd searches it second |
| `/etc/cni/net.d` | link to `/run/cni/net.d` | network add-ons write the CNI configuration there; containerd reads it |

The host ships what the CNI plugins it runs need, not what add-ons carry in their own images:

- Cilium and Calico install their own CNI plugins and run `iptables`/`nft` from their pods;
- flannel relies on the host's `bridge`, `host-local`, `loopback` and `portmap`;
- `portmap` (for `hostPort`) and `bridge` with masquerading run the host's `iptables`/`nft`, in
  `/usr/bin`, the `PATH` of containerd's (and so the plugins') and kubelet's services;
- kube-proxy carries its own tools in its image.

There are no `ebtables`/`arptables` names, and no `iptables-legacy`: the kernel has no legacy
tables.

## Kernel

The kernel is `standard`'s. Its configuration
(`specs/targets/standard/components/kernel/config.fragment`) covers what nodes need: kube-proxy in
its nftables and iptables-nft modes (`CONFIG_NETFILTER_XT_NAT` for `DNAT`/`SNAT`) and IPVS, bridges
and overlays, BPF with BTF (Cilium), and the keys kubelet checks (`CONFIG_KEYS`).

## Versions

The Kubernetes release is pinned once, by the target's `pause`, which exports it (`kubernetes`, with
`kubernetes-major` and `kubernetes-minor`). pause's source comes from that release, and kubelet's
`version` is `{pause.kubernetes}`, so the sandbox image and kubelet always match.

- A patch release is that one value and two checksums (pause's `pause.c`, kubelet's tarball).
- A minor release is a new target (`kubernetes-1-38`) with its own pause and kubelet recipes. The
  netfilter tools, the CNI plugins and `mount` then move to `specs/components/`, shared by both
  targets.

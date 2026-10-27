# The `kubernetes-1-37` target

An image that runs as a Kubernetes 1.37 node: `standard`, plus kubelet and what it runs on the host.
`cargo builder image --target kubernetes-1-37` builds `build/out/hardened-kubernetes-1-37-*`.

The target is `specs/targets/kubernetes-1-37/` (`extends = "standard"`, so it has every component
of `standard`). dust-init is the same binary as in `standard`: it runs kubelet because the image has
`/usr/bin/kubelet` and user-data enables it. The settings are in
[user-data.md](user-data.md#settingskubernetes); an overview is in
[architecture.md](architecture.md#kubernetes).

## Contents

Besides `standard`'s components:

| Component | Version | In the image | Notes |
| --- | --- | --- | --- |
| `kubelet` | 1.37.1 | `/usr/bin/kubelet` | Static Go, no libc |
| `cni-plugins` | 1.9.1 | `/usr/libexec/cni/{bridge,host-local,loopback,portmap}` | The reference plugins, static Go |
| `iptables` | 1.8.13 | `/usr/bin/xtables-nft-multi`, and `iptables`, `ip6tables`, their `-save`, `-restore` and `-nft` names | nf_tables backend only, extensions built in; fully static |
| `nftables` | 1.1.7 | `/usr/bin/nft` | Without the interactive CLI, with mini-gmp; fully static |
| `util-linux-mount` | 2.42.4 | `/usr/bin/mount`, `/usr/bin/umount` | kubelet mounts the tmpfs of secret and projected volumes, and bind mounts, with them |
| `libmnl`, `libnftnl` | 1.0.5, 1.3.2 | nothing | Static libraries linked into iptables and nft |

`kernel`, `containerd`, `runc`, `pause` and the others are `standard`'s builds: their recipes and
environments are the same, so the target reuses their cached builds.

## Running a node

When `settings.kubernetes.enabled` is set, dust-init:

1. before containerd starts:
   - sets `net.ipv4.ip_forward = 1` (before `settings.kernel.sysctl`, which can override it);
   - makes every mount shared, `/` recursively, for mount propagation (CSI drivers, Cilium);
   - writes kubelet's configuration to `/run/kubelet`: `config.json`, `bootstrap-kubeconfig`,
     `ca.crt`, the static pods in `manifests/` (secrets in files of mode 0600, in a directory of
     mode 0700);
2. starts containerd, imports the bundled images (the sandbox image is the bundled `pause`);
3. starts kubelet and supervises it like containerd: restarted with backoff, its output in
   `/var/log/kubelet.log` (copied and truncated past 64 MiB), the end of a crashed run copied to the
   console;
4. at shutdown, stops kubelet, then every container (its stop signal, then SIGKILL after 20 s) and
   pod sandbox through CRI, then containerd.

kubelet runs on the host, unconfined. Its configuration:

- the cgroupfs driver on cgroup v2 (there is no systemd), containerd's CRI socket
  (`unix:///run/containerd/containerd.sock`);
- TLS bootstrapping with the bootstrap token, then a rotated client certificate, kept with the rest
  of its state in `/var/lib/kubelet`;
- webhook authentication and authorization, no anonymous access, no read-only port;
- the node name is the machine's hostname; the node address is the one of the default route;
- the reservations, eviction thresholds and image garbage collection of user-data, when set;
- static pods from `/run/kubelet/manifests`, rewritten at every boot from user-data.

kubelet removes the pods it did not create, so dust-init runs no workload of its own on a node:
`settings.hardened.containers` is rejected and the workload calls of the API answer `unavailable`.
Static pods take their place.

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
- `portmap` (for `hostPort`) and `bridge` with masquerading run the host's `iptables`/`nft`, found
  in `/usr/bin`, the `PATH` dust-init gives containerd (and so the plugins) and kubelet;
- kube-proxy carries its own tools in its image.

There are no `ebtables`/`arptables` names, and no `iptables-legacy`: the kernel has no legacy
tables.

## Kernel

The kernel is `standard`'s. Its configuration
(`specs/targets/standard/components/kernel/config.fragment`) covers what nodes need: kube-proxy in
its nftables and iptables-nft modes (`CONFIG_NETFILTER_XT_NAT` for `DNAT`/`SNAT`) and IPVS, bridges
and overlays, BPF with BTF (Cilium), and the keys kubelet checks (`CONFIG_KEYS`).

## Versions

The Kubernetes release is pinned once, by `standard/pause`, which exports it (`kubernetes`, with
`kubernetes-major` and `kubernetes-minor`). pause's source comes from that release, and kubelet's
`version` is `{pause.kubernetes}`, so the sandbox image and kubelet always match.

- A patch release is that one value and two checksums (pause's `pause.c`, kubelet's tarball).
- A minor release is a new target (`kubernetes-1-38`) with its own kubelet recipe, overriding pause
  for its release. The netfilter tools, the CNI plugins and `mount` then move to
  `specs/components/`, shared by both targets.

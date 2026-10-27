# User-data reference

User-data is a TOML document in the Bottlerocket style. Settings are grouped under
`[settings.<group>]` and keys are kebab-case. The groups Bottlerocket has (`kernel`, `network`,
`dns`, `kubernetes`, `container-registry`) take its keys and value formats; hardened's own
settings are under `settings.hardened`. It may be plain, gzip-compressed, base64-encoded,
or base64 of gzip; dust-init detects which.

Unknown keys are rejected. If the user-data is invalid, dust-init logs the error on the console and
boots with defaults.

Where dust-init reads it:

| Platform | Source |
| --- | --- |
| Exoscale | metadata server `user-data` |
| qemu | fw_cfg entry `opt/hardened/user-data` (`cargo builder run --user-data FILE`) |

You can check a file locally with `cargo run -p dust-init -- check-user-data FILE`.

## `settings.kernel`

```toml
[settings.kernel.sysctl]
"net.ipv4.ip_forward" = "1"

[settings.kernel.modules.wireguard]
autoload = true

[settings.kernel.modules.sctp]
allowed = false
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `sysctl.<name>` | string | | Applied after the hardened defaults, so it can override them |
| `modules.<name>.autoload` | bool | `false` | Load this signed module (shipped in the image) and its dependencies at boot |
| `modules.<name>.allowed` | bool | `true` | When `false`, dust-init never loads the module, not even as a dependency of an `autoload` one |

The kernel never loads modules by itself (it has no modprobe helper), so `autoload` is the only
way a module gets loaded at boot. `allowed = false` with `autoload = true` is rejected. `allowed`
only steers dust-init: it does not restrict privileged workloads.

## `settings.network`

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `hostname` | string | from metadata, then DHCP, then `hardened-<instance-id>` | Hostname |

## `settings.dns`

```toml
[settings.dns]
name-servers = ["192.0.2.53", "2001:db8::53"]
search-list = ["corp.example.com"]
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `name-servers` | list of IPs | from DHCP | Replaces the DNS servers learned through DHCP. The resolver uses the first 3 |
| `search-list` | list of domain names | from DHCP | Replaces the search domains learned through DHCP. `resolv.conf` keeps the first 6 (glibc's limit), within 254 characters (musl's) |

## `settings.hardened.api`

Runs `dust-api`, a sandboxed process of dust-init that serves the API over mTLS. `hctl pki init` and
`hctl pki user-data` generate a ready-to-paste section.

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | |
| `listen` | socket address | `0.0.0.0:7443` | |
| `client-ca` | base64 PEM | required if enabled | CA that client certificates must chain to |
| `certificate` | base64 PEM | required if enabled | Server certificate chain |
| `private-key` | base64 PEM | required if enabled | Server key; redacted in `GetSettings` |

As in Bottlerocket (`settings.pki.*.data`), PEM values are the base64 of the whole PEM file
(`base64 -w0 server.pem`); line breaks in the base64 are ignored.

Client roles come from the certificate's Organization (O):

- `hardened:reader`: version, logs, settings, storage state, workload listing and logs,
  attestation evidence.
- `hardened:admin`: everything, including workload changes, reboot and shutdown.

## `settings.hardened.storage`

The state partition, mounted on `/var`: the only persistent storage.

```toml
[settings.hardened.storage]
encryption = "tpm"
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `encryption` | `none`, `tpm` | `none` | `tpm`: the partition is LUKS2, its key sealed to the TPM and PCR 11 (the booted image) |

With `tpm`, the machine needs a TPM 2.0 (a vTPM). The first boot formats the partition (what it
held is lost), and so does any boot whose TPM cannot unseal the key: **a new image starts with an
empty `/var`**, as does a cleared TPM or a disk moved to another machine. If the partition cannot
be set up otherwise (no TPM, a TPM or disk error), `/var` is a tmpfs: nothing is written to the
disk unencrypted.

Turning encryption off does not decrypt or wipe the partition: dust-init then leaves it alone and
`/var` is a tmpfs, until encryption is turned back on (invalid user-data falls back to the
defaults, which must not destroy the state). `hctl storage` shows what backs `/var` on this boot,
and why. See [state-encryption.md](state-encryption.md).

## `settings.kubernetes`

Runs kubelet, so the machine joins a Kubernetes cluster as a node. Only images that ship kubelet
(the `kubernetes-1-37` target, `hardened-kubernetes-1-37-*`) can: on another image, dust-init logs
an error and runs no kubelet. The keys are Bottlerocket's.

```toml
[settings.kubernetes]
enabled = true
api-server = "https://k8s.example.com:6443"
cluster-certificate = "LS0tLS1CRUdJTi..."   # base64 of the cluster CA's PEM
bootstrap-token = "abcdef.0123456789abcdef"
cluster-dns-ip = "10.96.0.10"
image-gc-high-threshold-percent = 85
image-gc-low-threshold-percent = 80

[settings.kubernetes.node-labels]
"node.kubernetes.io/pool" = "blue"

[settings.kubernetes.node-taints]
dedicated = ["gpu:NoSchedule"]

[settings.kubernetes.kube-reserved]
cpu = "100m"
memory = "512Mi"

[settings.kubernetes.system-reserved]
memory = "256Mi"

[settings.kubernetes.eviction-hard]
"memory.available" = "15%"
"nodefs.available" = "10%"

[settings.kubernetes.static-pods.log-shipper]
manifest = "YXBpVmVyc2lvbjogdjEK..."  # base64 of a Pod manifest, YAML or JSON
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `false` | |
| `api-server` | `https://` URL | required if enabled | The API server, with no path |
| `cluster-certificate` | base64 PEM | required if enabled | The cluster CA: kubelet checks the API server against it, and its own API accepts client certificates it signed (webhook authorization, no anonymous access) |
| `bootstrap-token` | `<6>.<16>` lowercase alphanumerics | required if enabled | TLS bootstrapping: kubelet requests its client certificate with it, then rotates it. Redacted in `GetSettings` |
| `cluster-domain` | domain name | `cluster.local` | |
| `cluster-dns-ip` | IP, or list of IPs | none | The cluster DNS service, given to pods |
| `node-labels` | table | | Labels the node registers with. kubelet may only set `kubernetes.io` and `k8s.io` labels of the `kubelet.kubernetes.io` and `node.kubernetes.io` namespaces, and a few well-known ones (`topology.kubernetes.io/zone`...): others (`node-role.kubernetes.io/*`) are rejected |
| `node-taints` | table of lists of `<value>:<effect>` | | Taints the node registers with; the value may be empty, the effect is `NoSchedule`, `PreferNoSchedule` or `NoExecute` |
| `max-pods` | 1 to 65535 | kubelet's (110) | |
| `cloud-provider` | `external` | none | A cloud controller manager initializes the node |
| `static-pods.<name>.manifest` | base64 of YAML or JSON | required | A Pod kubelet runs from a file, without the API server (it shows there as a mirror pod) |
| `static-pods.<name>.enabled` | bool | `true` | |
| `kube-reserved.<resource>`, `system-reserved.<resource>` | quantity (`100m`, `512Mi`, `1Gi`, `129e6`) | none | Resources kept from pods for Kubernetes daemons and the system; `<resource>` is `cpu`, `memory`, `ephemeral-storage` or `pid` |
| `eviction-hard.<signal>` | quantity, or percentage below 100 (`"15%"`) | kubelet's | Thresholds below which kubelet evicts pods; `<signal>` is `memory.available`, `nodefs.available`, `nodefs.inodesFree`, `imagefs.available`, `imagefs.inodesFree` or `pid.available`. Set, it replaces kubelet's defaults as a whole: a signal left out is not checked |
| `eviction-soft.<signal>` | quantity, or percentage below 100 | none | Thresholds below which kubelet evicts pods once they last `eviction-soft-grace-period`; same signals as `eviction-hard` |
| `eviction-soft-grace-period.<signal>` | duration (`1m30s`) | | How long a soft threshold must be crossed before evicting; one per `eviction-soft` signal, and only for those |
| `eviction-max-pod-grace-period` | 0 to 2147483647 (seconds) | kubelet's (`0`) | The longest a pod evicted on a soft threshold gets to stop |
| `image-gc-high-threshold-percent` | 0 to 100, number or string | 85 | Disk usage above which images are always collected |
| `image-gc-low-threshold-percent` | 0 to 100, number or string | 80 | Disk usage image collection brings it back to; must be below the high threshold (both checked, with kubelet's defaults for the one left out) |
| `image-minimum-gc-age` | duration (`1h30m`, `90s`; h, m, s, ms in that order) | `2m` | An unused image is not collected before |
| `image-maximum-gc-age` | duration | `0s` (off) | An image unused this long is collected; above `image-minimum-gc-age` |

`<name>` of a static pod: 1 to 63 characters, lowercase letters, digits or `-`, not starting with
`-`; it names the file (`/run/kubelet/manifests/<name>.yaml`, kubelet's `staticPodPath`, rewritten
at every boot), the pod's name is the manifest's. A manifest must be a single Pod
(`apiVersion: v1`, `kind: Pod`, with `metadata`): a JSON one is parsed, a YAML one only checked at
its top level, so kubelet reports other mistakes, in its log.

The node name is the hostname (`settings.network.hostname`, else the platform's); kubelet picks the
node's address itself, from the default route.

kubelet runs on the host, next to containerd, with the cgroupfs driver; its log is
`/var/log/kubelet.log`, and the end of a crashed run is copied to the console. dust-init writes its
configuration and credentials to `/run/kubelet` at every boot; kubelet keeps its state, its
rotated client certificate included, in `/var/lib/kubelet`. With kubelet enabled, dust-init also:

- sets `net.ipv4.ip_forward = 1` (before `settings.kernel.sysctl`, which can override it). IPv6
  forwarding is left to user-data: it stops the kernel from accepting router advertisements;
- makes every mount shared, for volumes with mount propagation (CSI drivers, Cilium);
- runs no workload of its own: `settings.hardened.containers` is rejected (kubelet stops the pods it did
  not create), and the workload calls of the API answer `unavailable`. Run them as static pods
  (`static-pods`) or through the cluster;
- at shutdown, stops kubelet, then every container (its stop signal, then SIGKILL after 20 s) and pod.

Pod networking comes from a cluster network add-on (Calico, Cilium, flannel...), installed as
usual: it writes its CNI plugins to `/opt/cni/bin` (a link to `/var/lib/cni/bin`) and its
configuration to `/etc/cni/net.d` (a link to `/run/cni/net.d`). The image ships the reference
`loopback`, `bridge`, `host-local` and `portmap` plugins in `/usr/libexec/cni`, which containerd
prefers, and the `iptables`/`ip6tables` (nf_tables backend only, `iptables-nft`) and `nft` commands
in `/usr/bin`, on the `PATH` of containerd, its plugins and kubelet.

## `settings.container-registry`

Registry mirrors and credentials, for every image pull: kubelet's pods and dust-init's workloads
(and kubelet's sandbox image is bundled, never pulled). The keys are Bottlerocket's.

```toml
[[settings.container-registry.mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com", "https://cache.example.com/v2/hub"]

[[settings.container-registry.mirrors]]
registry = "*"
endpoint = ["https://mirror.example.com"]

[[settings.container-registry.credentials]]
registry = "registry.example.com:5000"
username = "puller"
password = "s3cr3t"
```

`mirrors` (a list; Bottlerocket's former table of registry to endpoints is accepted too):

| Key | Type | Description |
| --- | --- | --- |
| `registry` | `[http://\|https://]<host>[:<port>]`, or `*` | The registry whose pulls the endpoints serve; `*` for every registry without mirrors of its own |
| `endpoint` | list of URLs | Tried in order, then the registry itself. An endpoint with a path replaces the registry's `/v2` path |

`credentials` (a list, also accepted as `creds`), one of `username` and `password`, `auth`, or
`identitytoken` per registry:

| Key | Type | Description |
| --- | --- | --- |
| `registry` | `[http://\|https://]<host>[:<port>]` | `docker.io` stands for Docker Hub's `registry-1.docker.io` |
| `username`, `password` | strings | Redacted (the password) in `GetSettings` |
| `auth` | base64 of `<username>:<password>` | Redacted in `GetSettings` |
| `identitytoken` | string | A registry identity token. Redacted in `GetSettings` |

A registry is reached with HTTPS, or HTTP when its scheme says so or its port is 80. Credentials
apply to pulls that carry none: a pod's image pull secrets take precedence.

**One `credentials` entry per host, mirrors included.** containerd looks credentials up by the
host it contacts: pulling `docker.io/library/nginx` through `mirror.example.com` asks for
`mirror.example.com`'s, not Docker Hub's. A registry's credentials are never copied to its
mirrors (as in Bottlerocket): give each mirror that needs them its own entry.

```toml
[[settings.container-registry.mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com"]

# Used when the mirror answers (registry-1.docker.io's would not be).
[[settings.container-registry.credentials]]
registry = "mirror.example.com"
username = "mirror-user"
password = "mirror-password"

# Used when the pull falls back to Docker Hub.
[[settings.container-registry.credentials]]
registry = "docker.io"
username = "hub-user"
password = "hub-password"
```

dust-init writes the mirrors as containerd `hosts.toml` files in `/run/containerd/certs.d` (its
`config_path`), and always runs containerd with a configuration it generates at every boot,
`/run/containerd/config.toml` (mode 0600): the image's, plus the credentials in the CRI plugin's
`configs`, even when there are none. `configs` is deprecated in containerd 2 and removed in 2.7;
credentials will then go through a credential helper, with the same settings.

## `settings.hardened.containers.<name>`

`<name>`: 1 to 63 characters, lowercase letters, digits or `-`, not starting with `-`.

```toml
[settings.hardened.containers.web]
image = "docker.io/library/nginx:1.29"
args = ["nginx", "-g", "daemon off;"]
env = { NGINX_PORT = "8080" }
restart = "always"
mounts = [{ source = "/var/lib/web", destination = "/usr/share/nginx/html", read-only = true }]
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | |
| `image` | string | required | Image reference |
| `command` | list | image entrypoint | Overrides the entrypoint |
| `args` | list | image command | Overrides the command |
| `env` | table | | Added to (and overriding) the image environment |
| `privileged` | bool | `false` | See below |
| `restart` | `always`, `on-failure`, `never` | `always` | Restarts use exponential backoff, from 1 s up to 60 s |
| `mounts` | list | | Bind mounts. `source` must be under `/var`; `read-only` is optional |
| `console` | bool | `false` | Also copy the workload's output to the serial console |

A workload is confined unless `privileged = true`: the runtime's default capabilities and seccomp
profile, `no_new_privs`, and masked or read-only kernel interfaces in `/proc` and `/sys`. A
privileged workload gets every capability, every host device, no seccomp filter, no
`no_new_privs`, and an unmasked, writable `/proc` and `/sys`. It still has its own mount and PID
namespaces, but it effectively controls the machine (host devices, sysctls, kernel modules).

Workloads use the host network. Logs are kept in `/var/log/containers/<name>.log` and can be
read with `hctl workloads logs <name>`.

Workloads applied through the API (`hctl workloads apply`) take the same settings. They are
stored in `/var/lib/dust` and restarted on every boot. The API cannot change or remove
workloads defined in user-data.

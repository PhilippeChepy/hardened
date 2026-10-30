# User-data reference

User-data is a TOML document. Settings are grouped under `[settings.<group>]` and keys are
kebab-case. It may be plain, gzip-compressed, base64-encoded, or base64 of gzip; machine-controller
detects which.

Where Bottlerocket has a setting (`kernel`, `network`, `dns`, `ntp`, `kubernetes`,
`container-registry`), hardened takes its keys and value formats, so the same TOML works on both;
hardened's own settings are under `settings.hardened`. Of Bottlerocket's settings, hardened
supports those listed here.

Unknown keys are rejected, and so is any value that could not be used: settings that only make
sense together are checked together (a module autoloaded must be allowed, a soft eviction
threshold needs its grace period, the low image GC threshold must be below the high one), and
alternatives exclude each other (one form of registry credentials). If the user-data is invalid,
machine-controller logs the error on the console and boots with defaults.

| Platform | User-data source |
| --- | --- |
| Exoscale | metadata server `user-data` |
| qemu | fw_cfg entry `opt/hardened/user-data` (`cargo builder run --user-data FILE`) |

To check a file locally:
`cargo run --manifest-path controllers/Cargo.toml -p machine-controller -- check-user-data FILE`.

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
| `modules.<name>.allowed` | bool | `true` | Whether machine-controller may load this signed module (shipped in the image) |
| `modules.<name>.autoload` | bool | `false` | Whether machine-controller loads it at boot, with its dependencies; an autoloaded module must be allowed |

A module allowed but not autoloaded is loaded when an autoloaded one needs it; one not allowed is
never loaded, not even as a dependency (an autoloaded module needing it is not loaded either).

The kernel never loads modules by itself (it has no modprobe helper), so `autoload` is the only
way a module gets loaded. `allowed = false` only steers machine-controller: it does not restrict
privileged workloads.

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

## `settings.ntp`

```toml
[settings.ntp]
time-servers = ["time.example.com", "192.0.2.123"]
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `time-servers` | list of host names or IPs | from DHCP, else `pool.ntp.org` | The NTP servers time-controller queries, in order of preference |

Without it, the servers come from DHCP (option 42), or else are `pool.ntp.org`, whose
[terms](https://www.ntppool.org/en/vendors.html) ask vendors for their own zone: set your
provider's or your own servers in production. See [Time](architecture.md#time).

## `settings.hardened.api`

Present, machine-apiproxy runs: a sandboxed service that serves the machine's API over mTLS.
`hctl pki init` and `hctl pki user-data` generate a ready-to-paste section.

```toml
[settings.hardened.api]
listen = "0.0.0.0:7443"
# A self-signed example, its own CA: use hctl pki's.
client-ca = """
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJlekNDQVNHZ0F3SUJBZ0lVWXZWeGt0Q3V2
NEJpWFFKWm1pVWVxTUpxY05Nd0NnWUlLb1pJemowRUF3SXcKRWpFUU1BNEdBMVVFQXd3SFpYaGhi
WEJzWlRBZ0Z3MHlOakV3TXpBeE16QTJOREphR0E4eU1USTJNVEF3TmpFegpNRFkwTWxvd0VqRVFN
QTRHQTFVRUF3d0haWGhoYlhCc1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VICkEwSUFC
SFc3a3hIK2l5SEhvcXZoZXltaVduTG9YaXA1ZGZLOG9BREw0Z1pqRzdtTXZjc1MzV0NYRHY5WDNy
R2MKUHJpMGZwU3UxT0RhWlJMc3NQY0U1WnFDaFVLalV6QlJNQjBHQTFVZERnUVdCQlJMdk43bU51
akUydzcyZnpvYgpLTTVaVWdqSThqQWZCZ05WSFNNRUdEQVdnQlJMdk43bU51akUydzcyZnpvYktN
NVpVZ2pJOGpBUEJnTlZIUk1CCkFmOEVCVEFEQVFIL01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lI
NHdILy9uQ1l1TnpESWh1UXROT2VhcXhzWkYKSUNaNWhqeSs0TnJhbzR5U0FpRUFxN0J4b0s0QnB6
dU5pL2pja3RRMXAwYXI4YnJSL1MwSVZPM09CaCtjSFpjPQotLS0tLUVORCBDRVJUSUZJQ0FURS0t
LS0tCg==
"""
certificate = """
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJlekNDQVNHZ0F3SUJBZ0lVWXZWeGt0Q3V2
NEJpWFFKWm1pVWVxTUpxY05Nd0NnWUlLb1pJemowRUF3SXcKRWpFUU1BNEdBMVVFQXd3SFpYaGhi
WEJzWlRBZ0Z3MHlOakV3TXpBeE16QTJOREphR0E4eU1USTJNVEF3TmpFegpNRFkwTWxvd0VqRVFN
QTRHQTFVRUF3d0haWGhoYlhCc1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VICkEwSUFC
SFc3a3hIK2l5SEhvcXZoZXltaVduTG9YaXA1ZGZLOG9BREw0Z1pqRzdtTXZjc1MzV0NYRHY5WDNy
R2MKUHJpMGZwU3UxT0RhWlJMc3NQY0U1WnFDaFVLalV6QlJNQjBHQTFVZERnUVdCQlJMdk43bU51
akUydzcyZnpvYgpLTTVaVWdqSThqQWZCZ05WSFNNRUdEQVdnQlJMdk43bU51akUydzcyZnpvYktN
NVpVZ2pJOGpBUEJnTlZIUk1CCkFmOEVCVEFEQVFIL01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lI
NHdILy9uQ1l1TnpESWh1UXROT2VhcXhzWkYKSUNaNWhqeSs0TnJhbzR5U0FpRUFxN0J4b0s0QnB6
dU5pL2pja3RRMXAwYXI4YnJSL1MwSVZPM09CaCtjSFpjPQotLS0tLUVORCBDRVJUSUZJQ0FURS0t
LS0tCg==
"""
private-key = """
LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JR0hBZ0VBTUJNR0J5cUdTTTQ5QWdFR0NDcUdT
TTQ5QXdFSEJHMHdhd0lCQVFRZ1NyR2tncTNvK0QwSGZDQTQKMGtZMFRjRlhUcEFpV3phYTlmTFpS
aVJhVXJHaFJBTkNBQVIxdTVNUi9vc2h4NktyNFhzcG9scHk2RjRxZVhYeQp2S0FBeStJR1l4dTVq
TDNMRXQxZ2x3Ny9WOTZ4bkQ2NHRINlVydFRnMm1VUzdMRDNCT1dhZ29WQwotLS0tLUVORCBQUklW
QVRFIEtFWS0tLS0tCg==
"""
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `listen` | socket address | `0.0.0.0:7443` | |
| `client-ca` | base64 PEM | required | CA that client certificates must chain to |
| `certificate` | base64 PEM | required | Server certificate chain |
| `private-key` | base64 PEM | required | Server key; redacted in `GetSettings` |

PEM values are the base64 of the whole PEM file (`base64 -w0 server.pem`); line breaks in the
base64 are ignored.

Client roles come from the certificate's Organization (O):

- `hardened:reader`: version, logs, settings, storage and time state, workload listing and logs,
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
disk unencrypted. Turning encryption off leaves an encrypted partition alone, with `/var` a tmpfs,
until it is turned back on. `hctl storage` shows what backs `/var` on this boot, and why. See
[state-encryption.md](state-encryption.md).

## `settings.kubernetes`

Present, kubelet runs, so the machine joins a Kubernetes cluster as a node. Only images that ship
kubelet (the `kubernetes-1-37` target, `hardened-kubernetes-1-37-*`) can: on another image,
machine-controller logs an error and runs no kubelet.

```toml
[settings.kubernetes]
api-server = "https://k8s.example.com:6443"
# The base64 of the cluster CA's PEM.
cluster-certificate = """
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJlekNDQVNHZ0F3SUJBZ0lVWXZWeGt0Q3V2
NEJpWFFKWm1pVWVxTUpxY05Nd0NnWUlLb1pJemowRUF3SXcKRWpFUU1BNEdBMVVFQXd3SFpYaGhi
WEJzWlRBZ0Z3MHlOakV3TXpBeE16QTJOREphR0E4eU1USTJNVEF3TmpFegpNRFkwTWxvd0VqRVFN
QTRHQTFVRUF3d0haWGhoYlhCc1pUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VICkEwSUFC
SFc3a3hIK2l5SEhvcXZoZXltaVduTG9YaXA1ZGZLOG9BREw0Z1pqRzdtTXZjc1MzV0NYRHY5WDNy
R2MKUHJpMGZwU3UxT0RhWlJMc3NQY0U1WnFDaFVLalV6QlJNQjBHQTFVZERnUVdCQlJMdk43bU51
akUydzcyZnpvYgpLTTVaVWdqSThqQWZCZ05WSFNNRUdEQVdnQlJMdk43bU51akUydzcyZnpvYktN
NVpVZ2pJOGpBUEJnTlZIUk1CCkFmOEVCVEFEQVFIL01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lI
NHdILy9uQ1l1TnpESWh1UXROT2VhcXhzWkYKSUNaNWhqeSs0TnJhbzR5U0FpRUFxN0J4b0s0QnB6
dU5pL2pja3RRMXAwYXI4YnJSL1MwSVZPM09CaCtjSFpjPQotLS0tLUVORCBDRVJUSUZJQ0FURS0t
LS0tCg==
"""
bootstrap-token = "abcdef.0123456789abcdef"
cluster-dns-ip = "10.96.0.10"
image-gc-high-threshold-percent = 85
image-gc-low-threshold-percent = 80
image-minimum-gc-age = "2m"
image-maximum-gc-age = "168h"

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

[settings.kubernetes.eviction-soft]
"memory.available" = "20%"

[settings.kubernetes.eviction-soft-grace-period]
"memory.available" = "1m30s"

[settings.kubernetes.static-pods.log-shipper]
# The base64 of a Pod manifest, YAML or JSON.
manifest = """
YXBpVmVyc2lvbjogdjEKa2luZDogUG9kCm1ldGFkYXRhOgogIG5hbWU6IGxvZy1zaGlwcGVyCnNw
ZWM6CiAgY29udGFpbmVyczoKICAtIG5hbWU6IHNoaXBwZXIKICAgIGltYWdlOiBkb2NrZXIuaW8v
Zmx1ZW50L2ZsdWVudC1iaXQ6NC4wCg==
"""
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `api-server` | `https://` URL | required | The API server, with no path |
| `cluster-certificate` | base64 PEM | required | The cluster CA: kubelet checks the API server against it, and its own API accepts client certificates it signed (webhook authorization, no anonymous access) |
| `bootstrap-token` | `<6>.<16>` lowercase alphanumerics | required | TLS bootstrapping: kubelet requests its client certificate with it, then rotates it. Redacted in `GetSettings` |
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
| `eviction-soft.<signal>` | quantity, or percentage below 100 | | A threshold below which kubelet evicts pods once it lasted its grace period; same signals as `eviction-hard` |
| `eviction-soft-grace-period.<signal>` | duration (`1m30s`) | | How long the soft threshold must be crossed before evicting. A threshold and its grace period come together: one without the other is rejected |
| `eviction-max-pod-grace-period` | 0 to 2147483647 (seconds) | kubelet's (`0`) | The longest a pod evicted on a soft threshold gets to stop |
| `image-gc-high-threshold-percent` | 0 to 100, a number or a string | `85` | Above it (percent of disk usage), kubelet collects images... |
| `image-gc-low-threshold-percent` | 0 to 100, a number or a string | `80` | ...until usage is back to it. It must be below the high threshold (the default standing for one left out) |
| `image-minimum-gc-age` | duration (`1h30m`, `90s`; h, m, s, ms in that order) | `2m` | An unused image is not collected before it |
| `image-maximum-gc-age` | duration | none (`0s`) | An unused image is always collected after it; `0s` turns it off. It must be above the minimum age (the default standing for one left out) |

`<name>` of a static pod: 1 to 63 characters, lowercase letters, digits or `-`, not starting with
`-`; it names the file (`/var/lib/kubelet/manifests/<name>.yaml`, kubelet's `staticPodPath`,
rewritten at every boot, where the manifests of pods no longer declared are removed), the pod's
name is the manifest's. A manifest must be a single Pod (`apiVersion: v1`, `kind: Pod`, with
`metadata`): a JSON one is parsed, a YAML one only checked at its top level, so kubelet reports
other mistakes, in its log.

The node name is the hostname (`settings.network.hostname`, else the platform's); kubelet picks
the node's address itself, from the default route. With kubelet running, machine-controller sets
`net.ipv4.ip_forward = 1` (before `settings.kernel.sysctl`, which can override it); IPv6
forwarding is left to user-data, as it stops the kernel from accepting router advertisements.
Workloads still run beside the pods, unseen by Kubernetes: keep their CPU and memory from the
pods with `system-reserved`.

How the node runs (kubelet's configuration, logs, shutdown) and pod networking are in
[kubernetes-target.md](kubernetes-target.md).

## `settings.hardened.containers.<name>`

`<name>`: 1 to 63 characters, lowercase letters, digits or `-`, not starting with `-`.

```toml
[settings.hardened.containers.web]
image = "docker.io/library/nginx:1.29"
command = ["nginx", "-g", "daemon off;"]
env.NGINX_PORT = "8080"
restart = "always"

[[settings.hardened.containers.web.mounts]]
source = "/var/lib/web"
destination = "/usr/share/nginx/html"
read-only = true
```

| Key | Type | Default | Description |
| --- | --- | --- | --- |
| `enabled` | bool | `true` | When `false`, declared (it owns its name) but not run |
| `image` | string | required | Image reference |
| `command` | list of strings, without NUL bytes | the image's entrypoint and command | The program and its arguments, replacing both (workloads run with `ctr run`, which cannot keep the entrypoint while replacing the command) |
| `env` | table of strings, without NUL bytes | | Added to (and overriding) the image environment |
| `privileged` | bool, or a table | `false` | See below |
| `restart` | `always`, `on-failure`, `never` | `always` | Restarts use exponential backoff, from 1 s up to 60 s |
| `mounts` | list | | Bind mounts. `source` must be under `/var` (created if missing, an existing directory left as it is) and, like `destination`, without commas; `read-only` is optional |
| `console` | bool | `false` | Also copy the workload's output to the serial console (user-data only: the API refuses it) |

A workload is confined unless `privileged = true`: the runtime's default capabilities and seccomp
profile, `no_new_privs`, and masked or read-only kernel interfaces in `/proc` and `/sys`. A
privileged workload gets every capability, every host device, no seccomp filter, no
`no_new_privs`, and an unmasked, writable `/proc` and `/sys`. It still has its own mount and PID
namespaces, but it effectively controls the machine (host devices, sysctls, kernel modules).

`privileged.host-root = "/host"` (a table in place of `true`) also mounts the host's `/` at
`/host` in the container, recursively read-only (`/var` and `/run` included): to inspect the
machine, with `hctl workloads exec` for instance. It is only possible for a privileged workload,
which could mount the host's filesystems itself anyway.

Each workload is a service, `workload-<name>` ([Workloads](architecture.md#workloads)), on the
host network. Its logs are in `/var/log/serviced/workload-<name>.log`
(`hctl workloads logs <name>`); `hctl workloads exec -it <name> -- sh` runs a shell in it.

Workloads applied through the API (`hctl workloads apply <name> --image <image> -- <command>...`)
take the same settings, and persist across reboots. User-data wins: the API cannot change or
remove its workloads, refuses their names, and an API workload whose name user-data declares later
is deleted.

## `settings.container-registry`

Registry mirrors and credentials, for every image pull: workloads' (`ctr images pull`, in
containerd's `system` namespace) and kubelet's pods' (through CRI). kubelet's sandbox image is
bundled, never pulled.

```toml
[[settings.container-registry.mirrors]]
registry = "docker.io"
endpoint = ["https://mirror.example.com", "https://cache.example.com/v2/hub"]

[[settings.container-registry.mirrors]]
registry = "*"
endpoint = ["https://mirror.example.com"]

[[settings.container-registry.mirrors]]
registry = "http://registry.local:5000"
endpoint = ["http://10.0.0.2:5000"]

[[settings.container-registry.credentials]]
registry = "registry.example.com:5000"
username = "puller"
password = "s3cr3t"

[[settings.container-registry.credentials]]
registry = "quay.io"
auth = "cHVsbGVyOnMzY3IzdA=="

[[settings.container-registry.credentials]]
registry = "ghcr.io"
identitytoken = "..."
```

A registry is `[http://|https://]<host>[:<port>]`, the host lowercase: Docker Hub is `docker.io`
(containerd's name, which stands for `registry-1.docker.io`). Without a scheme, it is reached with
HTTPS, or HTTP on port 80; the scheme only matters to a mirrored registry (Docker Hub is always
reached with HTTPS). A registry has at most one `mirrors` entry and one `credentials` entry: two
entries naming the same host, with or without a scheme, are rejected.

`[[mirrors]]`:

| Key | Type | Description |
| --- | --- | --- |
| `registry` | registry, or `*` | The mirrored registry; `*` for every registry without mirrors of its own |
| `endpoint` | non-empty list of URLs | Tried in order, then the registry itself. An endpoint with a path replaces the registry's `/v2` path |

Bottlerocket's former form, a table of registry to endpoints
(`[settings.container-registry.mirrors]` with `"docker.io" = ["https://mirror.example.com"]`), is
also accepted.

`[[credentials]]` (or `[[creds]]`): a `registry` (not `*`), and exactly one form of credentials:

| Key | Type | Description |
| --- | --- | --- |
| `username`, `password` | strings | The password is redacted in `GetSettings` |
| `auth` | base64 of `<username>:<password>` | As Docker's `config.json` holds it. Redacted in `GetSettings` |
| `identitytoken` | string | A registry identity token. Redacted in `GetSettings`. Kubernetes' pulls only |

Credentials apply to pulls that carry none: a pod's image pull secrets take precedence.

**Identity tokens are for Kubernetes only.** Workloads pull with `ctr`, which only sends what the
`hosts.toml` files hold: headers, so `username` and `password` or `auth` (as
`Authorization: Basic`). An identity token is an OAuth refresh token, which containerd's CRI
plugin exchanges for access tokens, and only CRI's pulls (kubelet's) use it. machine-controller
logs a warning for each one: workloads pull from its registry without credentials.

**Credentials per host, mirrors included.** containerd looks credentials up by the host it
contacts: pulling `docker.io/library/nginx` through `mirror.example.com` asks for
`mirror.example.com`'s, not Docker Hub's. A registry's credentials are never copied to its
mirrors: give each mirror that needs them its own entry.

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

machine-controller writes, at every boot, containerd `hosts.toml` files in
`/run/containerd/certs.d` (its `config_path`, mode 0600), which every pull reads: one per registry
with mirrors or with `username` and `password` or `auth` credentials. A host's credentials are
its `Authorization` header there, wherever it appears: as the registry of its file, or as a mirror
in another's. A registry with credentials but no mirrors of its own keeps those of `*`. The
credentials, identity tokens included, also go to the CRI plugin's `configs` of containerd's
configuration (`/run/containerd/config.toml`, mode 0600), for kubelet's pulls (deprecated in
containerd 2: see [known gaps](architecture.md#known-gaps--roadmap)).

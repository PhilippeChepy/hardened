# User-data reference

User-data is a TOML document in the Bottlerocket style. Settings are grouped under
`[settings.<group>]` and keys are kebab-case. It may be plain, gzip-compressed, base64-encoded,
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
| `search-list` | list of domain names | from DHCP | Replaces the search domains learned through DHCP. The resolver uses the first 6 |

## `settings.api`

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

- `hardened:reader`: version, logs, settings, workload listing and logs, attestation evidence.
- `hardened:admin`: everything, including workload changes, reboot and shutdown.

## `settings.containers.<name>`

`<name>`: 1 to 63 characters, lowercase letters, digits or `-`, not starting with `-`.

```toml
[settings.containers.web]
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

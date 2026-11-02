# Updating the recipes

`cargo builder update` moves the recipes to their upstreams' new releases: it finds them,
downloads and checks the new sources, rewrites the recipes' `version` and `sha256`, then builds
what changed and everything depending on it, putting back the updates that break a build. What
remains for the operator is the audit of the new sources, and the places the report names.

```sh
cargo builder update --dry-run          # the new releases, nothing downloaded or changed
cargo builder update                    # every recipe: rewrite, build, put back what breaks
cargo builder update kernel go          # some recipes (`<component>` or `<target>/<component>`)
cargo builder update --no-build         # rewrite only
```

## What it updates

A recipe with a literal release `version` (numbers separated by `.`, `-` or `_`, after an
optional word: `6.18.58`, `2026-10-20`, `stable202608`) and sources whose `url` names
`{version}`. Their `sha256` lines and the `version` line are rewritten in place; nothing else in
the file changes. Other recipes are reported as skipped, with the reason:

- **followers**, whose version is another recipe's (`version = "{nvidia-driver.version}"`):
  their own `{version}` sources move with the leader's, in the same update (one failure, or one
  failed build, puts the whole group back);
- recipes built from this repository (`workspace`), versions of other forms, recipes whose
  sources do not name their version (a commit), and those with `[update] manual`.

Sources pinned apart from the version (Rust's stage0 binaries, OVMF's submodule commits,
mimalloc in musl's recipe) are not touched: a build needing them changed fails, and the update
is put back.

## Where releases are found

Inferred from the main source's URL (`src`, else the first):

| URL | Releases |
| --- | --- |
| `github.com/<o>/<r>/archive/refs/tags/<tag>...`, `.../releases/download/<tag>/...` | the repository's tags matching `<tag>` |
| GitLab's `<repository>/-/archive/<tag>/...`, cgit's `<repository>/snapshot/...` | the repository's tags (`v{version}` for cgit) |
| `files.pythonhosted.org/packages/...` | PyPI's metadata, with each file's checksum |
| `go.dev/dl/...` | go.dev's release list, with each file's checksum |
| `static.rust-lang.org/dist/...` | Rust's stable channel |
| anything else | the directory listing above the URL's first part naming `{version}` |

Tags are read with git's smart HTTP protocol (`<repository>.git/info/refs`): no API, token or
rate limit. Pre-releases (anything but numbers after the first digit: `-rc1`, `b2`) are never
taken. A recipe adjusts this with an `[update]` table, after its sources:

```toml
[update]
track = "6.18"                # only releases of this series (6.18.x)
repository = "https://github.com/NVIDIA/open-gpu-kernel-modules"   # tags of another repository
tag = "{version}"             # its tags' form (default: the URL's, or `v{version}`)
listing = "https://musl.libc.org/releases.html"   # a page naming the files, for a host whose
                              # directories do not list
signature = "{url}.asc"       # each new source's detached OpenPGP signature
key = "musl"                  # its signers: specs/keys/musl.asc (or .gpg)
checksum = "{url}.sha256"     # or a checksum file the project publishes
manual = "why"                # updated by hand only
```

Without `track`, the newest release is taken, a new major version included: lines the images
pin (the kernel's long-term series, LLVM's major, Python's minor, NVIDIA's production branch,
OpenSSL 3, Perl's even minors) have their `track`; moving to another is a change by hand.

## How new sources are checked

The `sha256` written is the download's. Beyond it, each new source is checked as its project
allows, and the report says how:

1. **its detached OpenPGP signature**, against keys pinned in `specs/keys/`: the policy's
   `signature` and `key`, or GNU's `.sig` (key `gnu-keyring`) and Rust's `.asc` (key `rust`);
2. **kernel.org's signed `sha256sums.asc`** of the file's directory (key `kernel.org`), for
   sources on kernel.org;
3. **a checksum its index publishes** (PyPI, go.dev) or its project's checksum file
   (`checksum`, Rust's `.sha256`), over HTTPS;
4. otherwise, **UNCHECKED**, with the reason (no signature published, no key pinned).

A signature or checksum that does not match refuses the update. So does a signature by a key
not pinned: the report names its fingerprint, to pin once trusted (GNU's keyring, for one, lacks
some maintainers' current keys). Pinning a key is a trust decision, the operator's: the tool
never downloads keys.

## Building and putting back

Once rewritten, the updated recipes' units and every unit depending on them build (as
`cargo builder build --keep-going`). A failed unit puts back the update it belongs to, or, for a
unit depending on updates, every update it depends on; the rest builds again, until it builds.
A tool of the `tools` target changing rebuilds nearly everything: the update of a deep
component is a long run.

## The report

- **Updated**: each recipe's old and new version, how each source was checked, and the lines of
  the repository still naming the old version (version constants such as
  `plugin_workloads::DRA_VERSION`, documentation, the NVIDIA target's `prebuilt` paths): to
  update by hand, with the audit.
- **Put back**: the updates breaking a build, with the failure (logs in `build/logs/`).
- **Not updated**: refused downloads or checks, and recipes whose releases could not be found.
- **Up to date** and **Skipped**, with the reasons.

# State partition encryption

The state partition (partition 4, mounted on `/var`) is the only writable storage of the image:
the containerd store, kubelet's state and credentials, workload data. The root is read-only and
verified by dm-verity, but by default `/var` is a plain ext4 filesystem, readable from a copy of
the disk.

With encryption on, `/var` is a LUKS2 volume whose key is sealed to the machine's (v)TPM and to
the booted image. It is off by default:

```toml
[settings.hardened.storage]
encryption = "tpm"   # default "none"
```

The code is in [`crates/dust-init/src/storage/`](../crates/dust-init/src/storage/) (`encryption.rs`)
and [`crates/dust-init/src/attestation/tpm/`](../crates/dust-init/src/attestation/tpm/) (sealing).

## On disk

```text
partition 4 (systemd "var" type, grown to the end of the disk)
├── LUKS2 header, 16 MiB
│   ├── 2 × 16 KiB binary header + JSON metadata
│   │     label "hardened-state"
│   │     keyslot 0: luks2, PBKDF2-SHA256 with 1000 iterations, aes-xts-plain64
│   │     token 0:   hardened-tpm2 (below), bound to keyslot 0
│   └── keyslots area
└── data segment: aes-xts-plain64, 512-bit key (AES-256-XTS), 4 KiB sectors, "dynamic" size
    └── ext4, label STATE, 4 KiB blocks, 64bit, created at the first encrypted boot
```

The keyslot's passphrase is a random 256-bit secret, the **key** below; cryptsetup generates the
volume key itself and keeps it wrapped in the keyslot. Since the key is random, a slow PBKDF would
add nothing: the keyslot uses PBKDF2 with cryptsetup's minimum of 1000 iterations, so opening it
takes no memory and no time (argon2id, cryptsetup's default, is for passphrases people choose).

The token holds the key sealed by the TPM, and what it is bound to:

```json
{
  "type": "hardened-tpm2",
  "keyslots": ["0"],
  "tpm2-blob": "<base64 of the marshalled TPM2B_PRIVATE and TPM2B_PUBLIC>",
  "tpm2-pcrs": [11],
  "tpm2-pcr-bank": "sha256",
  "tpm2-primary-alg": "ecc",
  "tpm2-policy-hash": "<hex of the PolicyPCR digest sealed to>"
}
```

Its fields are those of systemd's `systemd-tpm2` token, with the same meanings (the blob has the
same layout), so tools that know one read the other. It is a type of its own because it is not
interchangeable: systemd seals under its own storage key (and salts, PINs, pcrlock policies...),
and passes the secret base64-encoded. Calling it `systemd-tpm2` would make systemd-cryptsetup try
it, and fail. `cryptsetup luksDump` shows it as is.

The filesystem cannot be created when the image is built (the key only exists on the machine), so
the image ships a static `mke2fs` and dust-init creates it, with the image's options (4 KiB blocks,
`64bit`, label `STATE`), without discard. `cryptsetup` is static too (OpenSSL's libcrypto, json-c,
libdevmapper, popt and libuuid linked in, with ThinLTO): see `cryptsetup-luks` and
`e2fsprogs-mke2fs` in [`specs/targets/standard/components/`](../specs/targets/standard/components/).

## The key

- **Bound to PCR 11.** systemd-stub measures the UKI's sections into PCR 11: the kernel, the
  command line (and so the dm-verity root hash) and os-release. The key unseals only on this TPM,
  booting this exact image. Any other image, even signed with the same Secure Boot key, cannot.
- **Sealing.** dust-init generates 32 random bytes (`getrandom`), reads PCR 11 (SHA-256 bank) and
  computes the PolicyPCR digest, then creates, under the storage key, a sealed data object
  (keyed hash) whose `authPolicy` is that digest, with `userWithAuth` clear (only the policy
  opens it), `fixedTPM`, `fixedParent` and `noDA`.
- **The storage key** is a primary key of the owner hierarchy, created at every boot from the
  TCG's ECC P-256 storage key template (restricted decryption key, AES-128-CFB, `noDA`). It is
  derived from the hierarchy's seed, so it is the same at every boot and nothing is persisted in
  the TPM; clearing the TPM changes it.
- **Unsealing.** dust-init loads the sealed object under the storage key, starts a policy session,
  runs TPM2_PolicyPCR on PCR 11 (the TPM uses the current values), and unseals with it. The
  session is flushed by the Unseal, the transient objects right after.
- **In memory only.** The key goes to `cryptsetup` on its standard input, never on a command line
  or in a file, and dust-init wipes its copies (the key, the TPM command and response buffers)
  when done. The volume key is in the dm-crypt table, in the kernel (cryptsetup is built without
  kernel keyring support), as with any dm-crypt volume.
- **No parameter encryption.** The secret crosses the TPM interface in clear (unsalted, unbound
  sessions). On a vTPM the hypervisor sees everything anyway; on a physical TPM, it is exposed to
  someone probing the bus.

## Boot

dust-init, after extending the partition to the end of the disk (on a MiB boundary, so it holds
whole 4 KiB sectors):

1. Opens the TPM. Without one, it stops here (see below).
2. Reads the start of the partition:
   - **LUKS2:** reads its metadata (`cryptsetup luksDump --dump-json-metadata`) and finds the
     `hardened-tpm2` token. If PCR 11's policy is the token's, it unseals the key and opens the
     volume (`cryptsetup open --key-file -`) as `/dev/mapper/state`. If the volume has no
     filesystem (a first boot stopped early), it creates it. It logs
     `state partition unlocked with the TPM`.
   - **LUKS2 that this boot cannot open** (no or a foreign token, PCR 11 differs, the TPM refuses
     the sealed object, the key opens no keyslot): it logs why, as a warning, then formats.
   - **ext4** (the image's empty filesystem, at first boot) **or anything else:** it formats.
3. **Formatting:** a new key, sealed first (the disk is untouched if the TPM fails), then
   `cryptsetup luksFormat`, `cryptsetup token import`, `cryptsetup open` and `mke2fs` on
   `/dev/mapper/state`. It logs `state partition formatted with encryption`.
4. Mounts `/dev/mapper/state` on `/var` and grows the filesystem online. The volume is opened
   after the partition is extended, and its data segment spans the partition, so a grown disk
   needs no `cryptsetup resize`.

## Failure behaviour

| Situation | Result |
| --- | --- |
| First boot (the image's ext4), or a partition with no known format | Formatted, encrypted |
| New image (PCR 11 differs), the TPM cleared or another TPM (the blob does not load: `TPM_RC_INTEGRITY`), a policy failure (`TPM_RC_POLICY_FAIL`) | Formatted, encrypted: **the state is lost**, logged as a warning |
| LUKS2 without a usable `hardened-tpm2` token, or whose keyslot the key does not open | Formatted, encrypted, logged as a warning |
| No TPM; any other TPM error (lockout, out of memory...); cryptsetup or mke2fs failing; an unreadable header | `/var` is a tmpfs, nothing persists; logged as an error. The partition is left as it is (or half formatted, which the next boot formats again) |

| Encryption off, and the partition is LUKS2 | `/var` is a tmpfs, logged as an error; the partition is left as it is |

Formatting is the answer only to a definite "this key is not for this boot": there is no recovery
key, so such a volume cannot be opened again on this machine anyway. Nodes are cattle: a node whose
state was lost starts over (a Kubernetes node re-registers, pulls its images again).

Other failures never fall back to an unencrypted `/var` on disk: when encryption was requested,
nothing reaches the disk in clear. The machine still boots, with `/var` in memory, so it stays
reachable through the API to read the error; workloads run, but keep nothing.

**What happened at boot** is in the API: `Machine/Storage` (`hctl storage`, readers may call it)
says whether `/var` is the plain partition, the encrypted one unlocked or formatted on this boot
(and why), or a tmpfs (and why), with the partition, the device mounted and its size:

```text
$ hctl storage
State:      encrypted state partition, formatted on this boot
Reason:     it could not be unlocked: its key is sealed to another image (PCR 11 differs)
Partition:  /dev/vda4
Device:     /dev/mapper/state
Size:       3.8 GiB, 3.6 GiB available
```

**Turning encryption off** does not wipe an encrypted partition: invalid user-data falls back to
the defaults, where encryption is off, and a typo must not destroy the state. Such a machine runs
with a tmpfs `/var` until encryption is turned back on, or the disk is replaced (or wiped) to start
over unencrypted. Turning it on formats an unencrypted partition, whatever it held.

## What it protects against

It protects the state disk at rest against copies: snapshots, a volume detached and attached
elsewhere, a disk image leaked from the provider. The copy is unreadable without this vTPM, in
this boot state.

It does not protect against:

- **Whoever runs the hypervisor:** the vTPM is theirs, and so is the memory holding the volume key.
  That holds for any cloud VM short of confidential computing (SEV-SNP, TDX).
- **Tampering:** dm-crypt hides the data, it does not authenticate it. A modified sector decrypts to
  garbage, which ext4's metadata checksums catch only for metadata. dm-integrity (AEAD) would add
  that, at a real cost in I/O and space; with a verity-protected root, confidentiality is the goal.
- **Anything running on the machine:** a privileged workload sees `/var` decrypted, and can read
  the dm-crypt table.
- **Size and usage patterns** are not hidden (no discard is passed through, though, so which blocks
  are in use is not revealed to the storage layer either).

## Choices

- **LUKS2 and a static cryptsetup**, rather than plain dm-crypt with a header of dust-init's own
  (less code in the image, but a format nobody else reads) or fscrypt (no reformatting, but file
  sizes and metadata stay in clear).
- **Plain PCR 11** rather than a signed PCR policy (`PolicyAuthorize` with ukify's `.pcrsig`), which
  would let any image we sign open the volume, and keep `/var` across image updates. Nodes are
  replaced rather than updated in place, and plain PCR 11 is the simplest and strictest. PCR 7
  (the Secure Boot state) alone is weaker: any image signed with the key would open it.
- **Reformat on a key that will not unseal**, rather than a recovery key (in user-data, it would
  weaken the protection; escrowed in a KMS, more machinery).
- **OpenSSL in user space for cryptsetup**, built without the kernel's crypto API (AF_ALG), so the
  kernel needs no `CRYPTO_USER_API_SKCIPHER`: only dm-crypt and the cipher
  (`CONFIG_DM_CRYPT`, `CONFIG_CRYPTO_AES`, `CONFIG_CRYPTO_AES_NI_INTEL`, `CONFIG_CRYPTO_XTS`).

## Tests

- Unit tests: the TPM commands against known byte sequences, the PolicyPCR digest against a value
  computed by a TPM, sealing and unsealing against a scripted TPM, the token, the partition probe,
  and the boot's decisions against a simulated partition and TPM (`storage::encryption::tests`).
- Against swtpm (ignored by default): sealing, unsealing in a new session, a tampered blob, an
  extended PCR 11 and another TPM:
  `nix shell nixpkgs#swtpm -c cargo test -p dust-init swtpm -- --ignored`.
- `cargo builder test` enables encryption in its user-data and boots six times on the same disk,
  with the swtpm state of the previous boot unless said otherwise:
  1. the image: it formats the partition;
  2. the image again: it unseals the key, opens the partition and finds the first boot's
     containerd store (`bundled image ... already imported`);
  3. another image: the image's test variant, a read-only disk holding only an ESP whose UKI has
     one more kernel option (`hardened.test-variant=1`), which the firmware boots, with the
     image's disk attached. The root filesystem is the same, PCR 11 is not: dust-init logs
     `its key is sealed to another image (PCR 11 differs)`, formats the partition again and
     imports the bundled images into an empty store;
  4. the test variant with a new swtpm state, as after clearing the TPM: dust-init logs `the TPM
     cannot unseal its key (another or a cleared TPM)` and formats the partition again;
  5. the test variant without a TPM: dust-init logs `cannot set up the encrypted state partition,
     /var will not persist`, leaves the partition alone and runs on a tmpfs `/var`;
  6. the test variant with the fourth boot's swtpm state: it unlocks the partition and finds the
     fourth boot's store, untouched by the fifth.

  `cargo builder test` writes the variant next to the image (`boot-variant.raw`); `cargo builder
  image` does not.

## Performance

dm-crypt costs CPU time on every read and write. Measured in the test VM (KVM on an AMD Ryzen 9
9950X, 2 vCPUs, 2 GiB, the qcow2 disk served from the host's page cache), with a privileged busybox
workload writing then reading back a 2 GiB file on `/var` (`dd bs=4M`, `conv=fsync` on writes, the
page cache dropped before reads), three runs each:

| `/var` | Guest CPU | dm-crypt's `xts(aes)` | Write | Read |
| --- | --- | --- | --- | --- |
| plain ext4 | `-cpu max` | | 2.5-2.7 GB/s | 13.6-15.7 GB/s |
| encrypted | `-cpu max` (AES-NI, VAES) | `xts-aes-vaes-avx512` | 1.9-2.2 GB/s | 9.8-10.4 GB/s |
| encrypted | `-cpu max,aes=off,vaes=off` | `xts(ecb(aes-generic))` | 573-591 MB/s | 754-764 MB/s |

With AES-NI, encryption costs about 20 % of writes and 30 % of reads on storage this fast, much
faster than any cloud volume. Without it the kernel falls back to its generic C AES, about 13 times
slower than VAES, still around 600 to 750 MB/s with two vCPUs: above what most cloud block storage
delivers, at the price of CPU time taken from workloads. Every x86-64 CPU a cloud offers today has
AES-NI; a VM whose CPU model hides it is the case to watch for. The numbers are one machine's, and
the plain baseline is bounded by the host's page cache, not a disk.

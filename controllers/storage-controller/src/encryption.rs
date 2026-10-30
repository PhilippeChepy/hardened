//! Encryption of the state partition: LUKS2 (aes-xts-plain64), unlocked by a random key sealed
//! to the TPM's PCR 11.
//!
//! trust-controller seals the key to PCR 11, where systemd-stub measures the UKI, so only this
//! TPM, booting this very image, unseals it. When it cannot (a new image, a cleared TPM, another
//! host), the partition is formatted again: nodes are cattle, and there is no recovery key to fall
//! back on. The sealed key lives in the LUKS2 header, as a `hardened-tpm2` token.
//!
//! `cryptsetup` and `mke2fs` (static, in the image) do the work; the key reaches them on their
//! standard input, never on a command line or in a file. A failure that is not a definite
//! "this key is not for this boot" (no TPM, a TPM or I/O error) leaves the partition alone.

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::path::Path;
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{Context as _, bail, ensure};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::runtime::Handle;
use tonic::Code;
use tonic::transport::Channel;
use tracing::{info, warn};
use trust_controller::trust::SealedSecret;
use trust_controller::trust::Secret;
use trust_controller::trust::sealing_client::SealingClient;
use zeroize::Zeroizing;

/// cryptsetup, which sets up LUKS2 volumes.
const CRYPTSETUP: &str = "/usr/bin/cryptsetup";
const MKE2FS: &str = "/usr/bin/mke2fs";
/// The device-mapper name of the decrypted partition.
const MAPPING: &str = "state";
/// What the decrypted partition is mounted from.
pub const MAPPED: &str = "/dev/mapper/state";
/// The LUKS2 token type holding the sealed key.
const TOKEN_TYPE: &str = "hardened-tpm2";
/// The keyslot the key opens, and the token's id.
const KEYSLOT: &str = "0";
/// Bounds each call to trust-controller: a TPM that does not answer leaves the partition alone.
const TRUST_CONTROLLER_TIMEOUT: Duration = Duration::from_secs(30);
/// A 256-bit random secret: the passphrase of the keyslot (cryptsetup generates the volume key).
const KEY_LEN: usize = 32;

/// What a partition holds, from its first 2 KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    /// A LUKS2 header.
    Luks2,
    /// ext2, 3 or 4 (they share their superblock magic).
    Ext4,
    /// Anything else, including nothing.
    Other,
}

impl Content {
    const PROBED: usize = 2048;

    /// What `head`, the first bytes of a partition, belongs to.
    #[must_use]
    pub fn of(head: &[u8]) -> Self {
        const LUKS_MAGIC: &[u8] = b"LUKS\xba\xbe";
        /// `s_magic`, at 56 in the superblock, itself at 1024.
        const EXT_MAGIC_AT: usize = 1024 + 56;
        if head.starts_with(LUKS_MAGIC) && head.get(6..8) == Some(&[0, 2]) {
            Self::Luks2
        } else if head.get(EXT_MAGIC_AT..EXT_MAGIC_AT + 2) == Some(&0xef53u16.to_le_bytes()) {
            Self::Ext4
        } else {
            Self::Other
        }
    }

    /// What `device` holds.
    pub fn probe(device: &Path) -> anyhow::Result<Self> {
        use std::io::Read as _;

        let mut head = vec![0; Self::PROBED];
        File::open(device)
            .and_then(|mut file| file.read_exact(&mut head))
            .with_context(|| format!("reading {}", device.display()))?;
        Ok(Self::of(&head))
    }
}

/// Unlocks the encrypted state partition `device` as [`MAPPED`], formatting it first when it
/// holds no state this boot can open. Blocking: `runtime` reaches trust-controller.
pub fn open(device: &Path, runtime: &Handle) -> anyhow::Result<Outcome> {
    // Without a TPM, serviced does not create trust-controller's socket.
    let socket = trust_controller::SOCKET;
    let channel = bounded(runtime, controllers_helpers::channel(Path::new(socket)))
        .and_then(|connected| Ok(connected?))
        .with_context(|| {
            format!("no TPM: trust-controller's socket {socket} cannot be connected to")
        })?;
    let mut partition = Partition {
        // An argument of cryptsetup's.
        device: (device.to_str()).with_context(|| format!("{} is not UTF-8", device.display()))?,
        sealing: SealingClient::new(channel),
        runtime,
    };
    let outcome = setup(&mut partition)?;
    match &outcome {
        Outcome::Unlocked => {
            info!(device = %device.display(), "state partition unlocked with the TPM")
        }
        Outcome::Formatted(_) => {
            info!(device = %device.display(), "state partition formatted with encryption")
        }
    }
    Ok(outcome)
}

/// Runs `call` to trust-controller on `runtime`, for [`TRUST_CONTROLLER_TIMEOUT`] at most.
fn bounded<T>(runtime: &Handle, call: impl Future<Output = T>) -> anyhow::Result<T> {
    runtime
        .block_on(async { tokio::time::timeout(TRUST_CONTROLLER_TIMEOUT, call).await })
        .with_context(|| {
            format!(
                "trust-controller did not answer within {}s",
                TRUST_CONTROLLER_TIMEOUT.as_secs()
            )
        })
}

/// What [`open`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Opened with the key the TPM unsealed.
    Unlocked,
    /// Formatted, and why.
    Formatted(String),
}

/// Opens the partition, or formats it when it holds no state this boot can open. Errors leave
/// it as it was, or half-formatted (which the next boot formats again).
fn setup(volume: &mut impl Volume) -> anyhow::Result<Outcome> {
    let reason = match volume.content()? {
        Content::Luks2 => match unlock(volume)? {
            Ok(()) => return Ok(Outcome::Unlocked),
            Err(lost) => {
                warn!(
                    reason = %lost,
                    "the encrypted state partition cannot be unlocked on this boot: formatting \
                     it, its contents are lost"
                );
                format!("it could not be unlocked: {lost}")
            }
        },
        Content::Ext4 => {
            info!("the state partition is not encrypted yet: formatting it with encryption");
            "it was not encrypted (first boot with encryption)".to_owned()
        }
        Content::Other => {
            warn!("the state partition holds no known format: formatting it with encryption");
            "it held no known format".to_owned()
        }
    };
    format(volume)?;
    Ok(Outcome::Formatted(reason))
}

/// Unseals the key and opens the partition with it; `Ok(Err(why))` when that can never work.
fn unlock(volume: &mut impl Volume) -> anyhow::Result<Result<(), String>> {
    let Some(token) = volume.token()? else {
        return Ok(Err(format!("its LUKS2 header has no {TOKEN_TYPE} token")));
    };
    let sealed = match token.sealed() {
        Ok(sealed) => sealed,
        Err(e) => return Ok(Err(format!("its {TOKEN_TYPE} token is unusable: {e:#}"))),
    };
    let key = match volume.unseal(&sealed).context("unsealing the key")? {
        Ok(key) => key,
        Err(why) => return Ok(Err(format!("its key cannot be unsealed: {why}"))),
    };
    if !volume.open(&key)? {
        return Ok(Err("the unsealed key opens none of its keyslots".to_owned()));
    }
    // An earlier first boot may have stopped before creating it.
    if !volume.has_filesystem()? {
        warn!("the encrypted state partition has no filesystem: creating it");
        volume.mkfs()?;
    }
    Ok(Ok(()))
}

/// Formats the partition as LUKS2 with a new key sealed to this boot, opens it and creates its
/// filesystem. The key is sealed before the disk is touched.
fn format(volume: &mut impl Volume) -> anyhow::Result<()> {
    let key = new_key()?;
    let sealed = volume.seal(&key).context("sealing the key")?;
    volume.format(&key, &Token::new(&sealed)?)?;
    ensure!(
        volume.open(&key)?,
        "the new key does not open the new LUKS2 volume"
    );
    volume.mkfs()
}

/// Closes [`MAPPED`], which removes the device-mapper table (and the volume key with it).
pub fn close() -> anyhow::Result<()> {
    run_ok(CRYPTSETUP, &["close", MAPPING], &[]).with_context(|| format!("{MAPPED} stays open"))?;
    info!(device = MAPPED, "encrypted state partition closed");
    Ok(())
}

/// Key material, zeroed when dropped.
type Key = Zeroizing<Vec<u8>>;

fn new_key() -> anyhow::Result<Key> {
    let mut key = Zeroizing::new(vec![0; KEY_LEN]);
    let mut filled = 0;
    while filled < KEY_LEN {
        filled +=
            rustix::rand::getrandom(&mut key[filled..], rustix::rand::GetRandomFlags::empty())
                .context("generating the key")?;
    }
    Ok(key)
}

/// The `hardened-tpm2` LUKS2 token: the key, as trust-controller sealed it. Its fields besides
/// `type` and `keyslots` are those of the sealed key, a JSON object (systemd's `systemd-tpm2`
/// token fields). It is not one (other templates, no salt or PIN): systemd-cryptsetup does not
/// try it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Token {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
    #[serde(flatten)]
    sealed: serde_json::Map<String, serde_json::Value>,
}

impl Token {
    /// The token of `sealed`, the key as trust-controller sealed it.
    fn new(sealed: &[u8]) -> anyhow::Result<Self> {
        let sealed =
            serde_json::from_slice(sealed).context("the sealed key is not a JSON object")?;
        Ok(Self {
            kind: TOKEN_TYPE.into(),
            keyslots: vec![KEYSLOT.to_owned()],
            sealed,
        })
    }

    /// The sealed key, if this token is one storage-controller wrote.
    fn sealed(&self) -> anyhow::Result<Vec<u8>> {
        ensure!(self.keyslots == [KEYSLOT], "keyslots {:?}", self.keyslots);
        Ok(serde_json::to_vec(&self.sealed).expect("a JSON object serializes"))
    }

    /// Our token among those of a LUKS2 header's JSON metadata.
    fn find(metadata: &[u8]) -> anyhow::Result<Option<Self>> {
        #[derive(Deserialize)]
        struct Metadata {
            #[serde(default)]
            tokens: BTreeMap<String, serde_json::Value>,
        }
        let metadata: Metadata =
            serde_json::from_slice(metadata).context("parsing the LUKS2 metadata")?;
        match metadata
            .tokens
            .into_values()
            .find(|token| token["type"] == TOKEN_TYPE)
        {
            Some(token) => Ok(Some(
                serde_json::from_value(token).context("parsing the token")?,
            )),
            None => Ok(None),
        }
    }
}

/// The effects of [`setup`], so that its decisions can be tested without a disk or a TPM.
trait Volume {
    fn content(&mut self) -> anyhow::Result<Content>;
    /// Our token in the LUKS2 header.
    fn token(&mut self) -> anyhow::Result<Option<Token>>;
    /// `key`, sealed to this boot.
    fn seal(&mut self, key: &[u8]) -> anyhow::Result<Vec<u8>>;
    /// The key `sealed` holds; `Ok(Err(why))` when it can never be unsealed on this boot.
    fn unseal(&mut self, sealed: &[u8]) -> anyhow::Result<Result<Key, String>>;
    /// Formats the partition as LUKS2, `key` opening its keyslot, with `token`.
    fn format(&mut self, key: &[u8], token: &Token) -> anyhow::Result<()>;
    /// Opens it as [`MAPPED`]; `false` when `key` opens no keyslot.
    fn open(&mut self, key: &[u8]) -> anyhow::Result<bool>;
    /// Whether [`MAPPED`] holds a filesystem.
    fn has_filesystem(&mut self) -> anyhow::Result<bool>;
    /// Creates the filesystem of [`MAPPED`].
    fn mkfs(&mut self) -> anyhow::Result<()>;
}

/// The state partition, with trust-controller and the programs that set it up.
struct Partition<'a> {
    device: &'a str,
    sealing: SealingClient<Channel>,
    runtime: &'a Handle,
}

/// Runs `program` with `args`, `input` on its standard input, and returns its exit status and
/// standard output. Its errors are logged when it fails.
///
/// # Panics
///
/// If `args` is empty: its first element names the operation in errors.
fn run(program: &str, args: &[&str], input: &[u8]) -> anyhow::Result<(ExitStatus, Vec<u8>)> {
    let context = || format!("running {program} {}", args[0]);
    let mut child = Command::new(program)
        .args(args)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(context)?;
    let mut stdin = child.stdin.take().expect("stdin is piped");
    // Written from another thread while the output is read, so neither side blocks on a full
    // pipe. `input` may be the key: it is written from where it is, never copied.
    let (written, output) = thread::scope(|scope| {
        let writer = scope.spawn(move || {
            use std::io::Write as _;
            stdin.write_all(input)
        });
        let output = child.wait_with_output();
        (writer.join(), output)
    });
    let output = output.with_context(context)?;
    match written {
        // A program exiting without reading its input is judged by its exit status.
        Ok(Err(e)) if e.kind() != io::ErrorKind::BrokenPipe => Err(e).with_context(context)?,
        Err(_) => bail!("writing the input of {program} panicked"),
        Ok(_) => {}
    }
    if !output.status.success() {
        for line in String::from_utf8_lossy(&output.stderr).lines() {
            warn!("{program}: {line}");
        }
    }
    Ok((output.status, output.stdout))
}

/// Runs `program` with `args`, failing unless it succeeds.
fn run_ok(program: &str, args: &[&str], input: &[u8]) -> anyhow::Result<Vec<u8>> {
    match run(program, args, input)? {
        (status, stdout) if status.success() => Ok(stdout),
        (status, _) => bail!("{program} {} failed with {status}", args[0]),
    }
}

impl Volume for Partition<'_> {
    fn content(&mut self) -> anyhow::Result<Content> {
        Content::probe(Path::new(self.device))
    }

    fn token(&mut self) -> anyhow::Result<Option<Token>> {
        let args = ["luksDump", "--dump-json-metadata", self.device];
        Token::find(&run_ok(CRYPTSETUP, &args, &[])?)
    }

    fn seal(&mut self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
        // tonic takes the request: the copy it encodes is wiped once its last reference is gone.
        let secret = Secret {
            secret: Bytes::from_owner(Zeroizing::new(key.to_vec())),
        };
        let sealed =
            bounded(self.runtime, self.sealing.seal(secret))?.context("trust-controller")?;
        Ok(sealed.into_inner().sealed)
    }

    fn unseal(&mut self, sealed: &[u8]) -> anyhow::Result<Result<Key, String>> {
        let sealed = SealedSecret {
            sealed: sealed.to_vec(),
        };
        match bounded(self.runtime, self.sealing.unseal(sealed))? {
            // A view of tonic's decode buffer, copied out to be wiped.
            Ok(secret) => Ok(Ok(Zeroizing::new(secret.into_inner().secret.to_vec()))),
            // Never unsealable: another image or TPM, or a token it did not write.
            Err(status)
                if matches!(
                    status.code(),
                    Code::FailedPrecondition | Code::InvalidArgument
                ) =>
            {
                Ok(Err(status.message().to_owned()))
            }
            Err(status) => Err(status).context("trust-controller"),
        }
    }

    fn format(&mut self, key: &[u8], token: &Token) -> anyhow::Result<()> {
        let device = self.device;
        // The key is random: a slow PBKDF would add nothing (cryptsetup's minimum for PBKDF2).
        #[rustfmt::skip]
        let args = [
            "luksFormat", "--batch-mode", "--type", "luks2",
            "--cipher", "aes-xts-plain64", "--key-size", "512", "--sector-size", "4096",
            "--hash", "sha256", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
            "--label", "hardened-state", "--key-slot", KEYSLOT, "--key-file", "-", device,
        ];
        run_ok(CRYPTSETUP, &args, key)?;
        let token = serde_json::to_vec(token)?;
        let args = [
            "token",
            "import",
            "--token-id",
            KEYSLOT,
            "--json-file",
            "-",
            device,
        ];
        run_ok(CRYPTSETUP, &args, &token)?;
        Ok(())
    }

    fn open(&mut self, key: &[u8]) -> anyhow::Result<bool> {
        #[rustfmt::skip]
        let args = [
            "open", "--type", "luks2", "--key-slot", KEYSLOT, "--key-file", "-",
            self.device, MAPPING,
        ];
        let (status, _) = run(CRYPTSETUP, &args, key)?;
        match status.code() {
            Some(0) => {}
            // No keyslot opens with this key.
            Some(2) => return Ok(false),
            _ => bail!("{CRYPTSETUP} open failed with {status}"),
        }
        // libdevmapper creates the node itself (there is no udev).
        ensure!(Path::new(MAPPED).exists(), "{MAPPED} did not appear");
        Ok(true)
    }

    fn has_filesystem(&mut self) -> anyhow::Result<bool> {
        Ok(Content::probe(Path::new(MAPPED))? == Content::Ext4)
    }

    fn mkfs(&mut self) -> anyhow::Result<()> {
        // As the image's: 4 KiB blocks (one per encryption sector), 64-bit, labelled STATE. No
        // discard: dm-crypt does not pass discards through, and they would reveal what is used.
        #[rustfmt::skip]
        let args = [
            "-q", "-F", "-t", "ext4", "-b", "4096", "-O", "64bit", "-L", "STATE",
            "-E", "nodiscard,root_owner=0:0", MAPPED,
        ];
        run_ok(MKE2FS, &args, &[])?;
        info!("state filesystem created");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_the_partition_contents() {
        let mut head = vec![0; Content::PROBED];
        assert_eq!(Content::of(&head), Content::Other);
        head[1080..1082].copy_from_slice(&[0x53, 0xef]);
        assert_eq!(Content::of(&head), Content::Ext4);
        head[..8].copy_from_slice(b"LUKS\xba\xbe\x00\x02");
        assert_eq!(Content::of(&head), Content::Luks2);
        head[..8].copy_from_slice(b"LUKS\xba\xbe\x00\x01");
        assert_eq!(Content::of(&head), Content::Ext4, "LUKS1 is not ours");
        assert_eq!(Content::of(b"LUKS\xba\xbe"), Content::Other);
    }

    /// A key as trust-controller seals it.
    const SEALED: &[u8] = br#"{"tpm2-blob":"AAMBAgMAAgQF","tpm2-pcrs":[11],
        "tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc",
        "tpm2-policy-hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#;

    fn sealed_value() -> serde_json::Value {
        serde_json::from_slice(SEALED).unwrap()
    }

    #[test]
    fn finds_its_token_among_others() {
        let token = Token::new(SEALED).unwrap();
        let metadata = serde_json::json!({
            "keyslots": {},
            "tokens": {
                "0": { "type": "systemd-recovery", "keyslots": ["1"] },
                "1": token,
            },
        });
        let found = Token::find(&serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert_eq!(found.as_ref(), Some(&token));
        let sealed = found.unwrap().sealed().unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&sealed).unwrap(),
            sealed_value()
        );
        assert_eq!(Token::find(br#"{"tokens": {}}"#).unwrap(), None);
        assert_eq!(Token::find(br#"{"keyslots": {}}"#).unwrap(), None);
        assert!(Token::find(b"not json").is_err());
        assert!(Token::new(b"[1, 2]").is_err(), "not an object");
    }

    /// `cryptsetup luksDump --dump-json-metadata` of a volume formatted and given a token as
    /// storage-controller does: the on-disk format.
    #[test]
    fn finds_the_token_in_cryptsetup_output() {
        let dump = br#"{
  "keyslots":{"0":{"type":"luks2","key_size":64,
    "af":{"type":"luks1","stripes":4000,"hash":"sha256"},
    "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64",
      "key_size":64},
    "kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,
      "salt":"2Lmy1zkv+B79BU3ofy3kpLxK7LxisITzu8l+uuvWQUk="}}},
  "tokens":{"0":{"type":"hardened-tpm2","keyslots":["0"],"tpm2-blob":"AAMBAgMAAgQF",
    "tpm2-pcrs":[11],"tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc",
    "tpm2-policy-hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
  "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0",
    "encryption":"aes-xts-plain64","sector_size":4096}},
  "digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256",
    "iterations":1000,"salt":"F31p9rLN0OOdLYVWk8QkWzx4E++EfqpbBpvrkAT+FRE=",
    "digest":"L/6a+/AoypTBD9QLBIjRSYSHXJmvjNq9BspcWhA6EMM="}},
  "config":{"json_size":"12288","keyslots_size":"16744448"}
}"#;
        let token = Token::find(dump).unwrap().unwrap();
        assert_eq!(token, Token::new(SEALED).unwrap());
    }

    /// A partition and trust-controller in memory, recording what was done.
    #[derive(Default)]
    struct Fake {
        content: Option<Content>,
        token: Option<Token>,
        /// The booted image, which keys are sealed to.
        image: u8,
        /// What trust-controller answers to Unseal (the key when `None`).
        unseal_error: Option<Code>,
        /// The key the keyslot takes.
        keyslot: Option<Vec<u8>>,
        filesystem: bool,
        fail_open: bool,
        log: Vec<&'static str>,
    }

    impl Volume for Fake {
        fn content(&mut self) -> anyhow::Result<Content> {
            self.content.context("unreadable")
        }

        fn token(&mut self) -> anyhow::Result<Option<Token>> {
            Ok(self.token.clone())
        }

        fn seal(&mut self, key: &[u8]) -> anyhow::Result<Vec<u8>> {
            self.log.push("seal");
            Ok(serde_json::to_vec(
                &serde_json::json!({ "key": key, "image": self.image }),
            )?)
        }

        fn unseal(&mut self, sealed: &[u8]) -> anyhow::Result<Result<Key, String>> {
            #[derive(Deserialize)]
            struct Sealed {
                key: Vec<u8>,
                image: u8,
            }

            self.log.push("unseal");
            match self.unseal_error {
                Some(Code::FailedPrecondition) => Ok(Err("another TPM".into())),
                Some(code) => bail!("trust-controller: {code:?}"),
                None => {
                    let sealed: Sealed = serde_json::from_slice(sealed)?;
                    if sealed.image == self.image {
                        Ok(Ok(Zeroizing::new(sealed.key)))
                    } else {
                        Ok(Err("sealed to another image (PCR 11 differs)".into()))
                    }
                }
            }
        }

        fn format(&mut self, key: &[u8], token: &Token) -> anyhow::Result<()> {
            self.log.push("format");
            self.content = Some(Content::Luks2);
            self.token = Some(token.clone());
            self.keyslot = Some(key.to_vec());
            self.filesystem = false;
            Ok(())
        }

        fn open(&mut self, key: &[u8]) -> anyhow::Result<bool> {
            self.log.push("open");
            ensure!(!self.fail_open, "device-mapper error");
            Ok(self.keyslot.as_deref() == Some(key))
        }

        fn has_filesystem(&mut self) -> anyhow::Result<bool> {
            Ok(self.filesystem)
        }

        fn mkfs(&mut self) -> anyhow::Result<()> {
            self.log.push("mkfs");
            self.filesystem = true;
            Ok(())
        }
    }

    /// A fake whose partition was formatted on a boot of `image`.
    fn formatted(image: u8) -> Fake {
        let mut fake = Fake {
            content: Some(Content::Ext4),
            image,
            ..Fake::default()
        };
        assert_eq!(
            formatted_because(&mut fake),
            "it was not encrypted (first boot with encryption)"
        );
        fake.log.clear();
        fake
    }

    /// Runs [`setup`], expecting it to format: why it did.
    fn formatted_because(fake: &mut Fake) -> String {
        match setup(fake).unwrap() {
            Outcome::Formatted(reason) => reason,
            Outcome::Unlocked => panic!("unlocked"),
        }
    }

    #[test]
    fn first_boot_formats_then_later_boots_unlock() {
        let mut fake = formatted(1);
        assert!(fake.filesystem);
        assert_eq!(fake.keyslot.as_ref().map(Vec::len), Some(KEY_LEN));

        assert_eq!(setup(&mut fake).unwrap(), Outcome::Unlocked);
        assert_eq!(fake.log, ["unseal", "open"]);
    }

    #[test]
    fn seals_before_touching_the_disk() {
        let mut fake = Fake {
            content: Some(Content::Other),
            ..Fake::default()
        };
        assert_eq!(formatted_because(&mut fake), "it held no known format");
        assert_eq!(fake.log, ["seal", "format", "open", "mkfs"]);
    }

    #[test]
    fn another_image_reformats() {
        let mut fake = formatted(1);
        let old_key = fake.keyslot.clone();
        fake.image = 2;
        assert_eq!(
            formatted_because(&mut fake),
            "it could not be unlocked: its key cannot be unsealed: sealed to another image (PCR \
             11 differs)"
        );
        assert_eq!(fake.log, ["unseal", "seal", "format", "open", "mkfs"]);
        assert_ne!(fake.keyslot, old_key);

        // The new key is sealed to the new image.
        fake.log.clear();
        assert_eq!(setup(&mut fake).unwrap(), Outcome::Unlocked);
    }

    #[test]
    fn a_tpm_that_cannot_unseal_reformats() {
        let mut fake = formatted(1);
        fake.unseal_error = Some(Code::FailedPrecondition);
        let reason = formatted_because(&mut fake);
        assert!(
            reason.contains("cannot be unsealed: another TPM"),
            "{reason}"
        );
    }

    #[test]
    fn unexpected_failures_leave_the_partition_alone() {
        // trust-controller failing for reasons that say nothing about the key (a TPM lockout).
        for code in [Code::Internal, Code::Unavailable] {
            let mut fake = formatted(1);
            fake.unseal_error = Some(code);
            assert!(setup(&mut fake).is_err(), "{code:?}");
            assert_eq!(fake.log, ["unseal"]);
        }
        let mut fake = formatted(1);
        fake.fail_open = true;
        assert!(setup(&mut fake).is_err());
        assert!(!fake.log.contains(&"format"));
        let mut fake = Fake::default();
        assert!(setup(&mut fake).is_err(), "unreadable partition");
        assert!(fake.log.is_empty());
    }

    #[test]
    fn luks2_without_a_usable_token_reformats() {
        let mut fake = formatted(1);
        fake.token = None;
        assert!(formatted_because(&mut fake).contains("no hardened-tpm2 token"));

        let mut fake = formatted(1);
        fake.token.as_mut().unwrap().keyslots = vec!["1".into()];
        assert!(formatted_because(&mut fake).contains("token is unusable"));

        // The token's key does not open the keyslot.
        let mut fake = formatted(1);
        fake.keyslot = Some(vec![0; KEY_LEN]);
        assert!(formatted_because(&mut fake).contains("opens none of its keyslots"));
        assert_eq!(
            fake.log,
            ["unseal", "open", "seal", "format", "open", "mkfs"]
        );
    }

    #[test]
    fn an_interrupted_first_boot_creates_the_filesystem() {
        let mut fake = formatted(1);
        fake.filesystem = false;
        assert_eq!(setup(&mut fake).unwrap(), Outcome::Unlocked);
        assert_eq!(fake.log, ["unseal", "open", "mkfs"]);
    }
}

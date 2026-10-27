//! Encryption of the state partition: LUKS2 (aes-xts-plain64), unlocked by a random key sealed to
//! the TPM's PCR 11.
//!
//! systemd-stub measures the UKI (kernel, command line with the verity root hash, os-release) into
//! PCR 11, so only this TPM, booting this very image, unseals the key. When it cannot (a new
//! image, a cleared TPM, another host), the partition is formatted again: nodes are cattle, and
//! there is no recovery key to fall back on. The sealed key lives in the LUKS2 header, as a
//! `hardened-tpm2` token.
//!
//! `cryptsetup` and `mke2fs` (static, in the image) do the work; the key reaches them on their
//! standard input, never on a command line or in a file. A failure that is not a definite
//! "this key is not for this boot" (no TPM, a TPM or I/O error) leaves the partition alone.

use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use zeroize::Zeroizing;

use crate::attestation::{Sealed, Tpm, TpmError};
use crate::process::{Exit, Reaper};

const CRYPTSETUP: &str = "/usr/bin/cryptsetup";
const MKE2FS: &str = "/usr/bin/mke2fs";
/// The device-mapper name of the decrypted partition.
const MAPPING: &str = "state";
/// What the decrypted partition is mounted from.
pub const MAPPED: &str = "/dev/mapper/state";
/// systemd-stub measures the UKI into PCR 11.
const PCRS: [u32; 1] = [11];
/// The LUKS2 token type holding the sealed key.
const TOKEN_TYPE: &str = "hardened-tpm2";
/// The keyslot the key opens, and the token's id.
const KEYSLOT: u32 = 0;
/// A 256-bit random secret: the passphrase of the keyslot (cryptsetup generates the volume key).
const KEY_LEN: usize = 32;

/// What a partition holds, from its first 2 KiB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Content {
    Luks2,
    /// ext2, 3 or 4 (they share their superblock magic).
    Ext4,
    Other,
}

impl Content {
    const PROBED: usize = 2048;

    pub fn of(head: &[u8]) -> Self {
        const LUKS_MAGIC: &[u8] = b"LUKS\xba\xbe";
        /// `s_magic`, at 56 in the superblock, itself at 1024.
        const EXT_MAGIC_AT: usize = 1024 + 56;
        if head.starts_with(LUKS_MAGIC) && head.get(6..8) == Some(&[0, 2]) {
            Self::Luks2
        } else if head.get(EXT_MAGIC_AT..EXT_MAGIC_AT + 2) == Some(&0xEF53u16.to_le_bytes()) {
            Self::Ext4
        } else {
            Self::Other
        }
    }

    pub fn probe(device: &Path) -> anyhow::Result<Self> {
        let mut head = vec![0; Self::PROBED];
        File::open(device)
            .and_then(|mut file| file.read_exact(&mut head))
            .with_context(|| format!("reading {}", device.display()))?;
        Ok(Self::of(&head))
    }
}

/// Unlocks the encrypted state partition `device` as [`MAPPED`], formatting it first when it
/// holds no state this boot can open.
pub async fn open(reaper: &Reaper, device: &Path) -> anyhow::Result<Outcome> {
    let tpm = tokio::task::spawn_blocking(|| Tpm::open(Path::new(Tpm::DEVICE)))
        .await?
        .context("opening the TPM")?
        .context("no TPM: the state partition's key cannot be sealed")?;
    let mut partition = Partition {
        reaper,
        device,
        tpm: Some(tpm),
    };
    let outcome = setup(&mut partition).await?;
    match &outcome {
        Outcome::Unlocked => info!(device = %device.display(), "state partition unlocked with the TPM"),
        Outcome::Formatted(_) => info!(device = %device.display(), "state partition formatted with encryption"),
    }
    Ok(outcome)
}

/// What [`open`] did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    Unlocked,
    /// Formatted, and why.
    Formatted(String),
}

/// Why an encrypted partition can never be unlocked on this boot.
#[derive(Debug)]
enum Lost {
    NoToken,
    BadToken(String),
    OtherImage,
    Unsealable(TpmError),
    WrongKey,
}

impl fmt::Display for Lost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoToken => write!(f, "its LUKS2 header has no {TOKEN_TYPE} token"),
            Self::BadToken(why) => write!(f, "its {TOKEN_TYPE} token is unusable: {why}"),
            Self::OtherImage => f.write_str("its key is sealed to another image (PCR 11 differs)"),
            Self::Unsealable(e) => write!(f, "the TPM cannot unseal its key (another or a cleared TPM): {e}"),
            Self::WrongKey => f.write_str("the unsealed key opens none of its keyslots"),
        }
    }
}

/// Opens the partition, or formats it when it holds no state this boot can open. Errors leave
/// it as it was, or half-formatted (which the next boot formats again).
async fn setup(v: &mut impl Volume) -> anyhow::Result<Outcome> {
    let reason = match v.content()? {
        Content::Luks2 => match unlock(v).await? {
            Ok(()) => return Ok(Outcome::Unlocked),
            Err(lost) => {
                warn!(
                    reason = %lost,
                    "the encrypted state partition cannot be unlocked on this boot: formatting it, its contents are lost"
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
    format(v).await?;
    Ok(Outcome::Formatted(reason))
}

/// Unseals the key and opens the partition with it; `Ok(Err(_))` when that can never work.
async fn unlock(v: &mut impl Volume) -> anyhow::Result<Result<(), Lost>> {
    let Some(token) = v.token().await? else {
        return Ok(Err(Lost::NoToken));
    };
    let (sealed, policy) = match token.parse() {
        Ok(parsed) => parsed,
        Err(e) => return Ok(Err(Lost::BadToken(format!("{e:#}")))),
    };
    if v.policy().await.context("reading PCR 11")? != policy {
        return Ok(Err(Lost::OtherImage));
    }
    let key = match v.unseal(&sealed).await {
        Ok(key) => key,
        Err(e) if e.is_sealed_elsewhere() => return Ok(Err(Lost::Unsealable(e))),
        Err(e) => return Err(e).context("unsealing the key"),
    };
    if !v.open(&key).await? {
        return Ok(Err(Lost::WrongKey));
    }
    // An earlier first boot may have stopped before creating it.
    if !v.has_filesystem()? {
        warn!("the encrypted state partition has no filesystem: creating it");
        v.mkfs().await?;
    }
    Ok(Ok(()))
}

/// Formats the partition as LUKS2 with a new key sealed to this boot, opens it and creates its
/// filesystem. The TPM seals the key before the disk is touched.
async fn format(v: &mut impl Volume) -> anyhow::Result<()> {
    let policy = v.policy().await.context("reading PCR 11")?;
    let key = new_key()?;
    let sealed = v.seal(&key, policy).await.context("sealing the key")?;
    v.format(&key, &Token::new(&sealed, &policy)).await?;
    ensure!(v.open(&key).await?, "the new key does not open the new LUKS2 volume");
    v.mkfs().await
}

type Key = Zeroizing<Vec<u8>>;

fn new_key() -> anyhow::Result<Key> {
    let mut key = Zeroizing::new(vec![0; KEY_LEN]);
    let mut filled = 0;
    while filled < KEY_LEN {
        filled += rustix::rand::getrandom(&mut key[filled..], rustix::rand::GetRandomFlags::empty())
            .context("generating the key")?;
    }
    Ok(key)
}

/// The `hardened-tpm2` LUKS2 token: the sealed key and what it is bound to. Its fields are those
/// of systemd's `systemd-tpm2` token with the same meaning; it is not one (other templates, no
/// salt or PIN), so systemd-cryptsetup does not try it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
struct Token {
    #[serde(rename = "type")]
    kind: String,
    keyslots: Vec<String>,
    /// base64 of the marshalled TPM2B_PRIVATE and TPM2B_PUBLIC of the sealed object.
    tpm2_blob: String,
    tpm2_pcrs: Vec<u32>,
    tpm2_pcr_bank: String,
    /// The storage key the object was created under (ECC P-256, the owner hierarchy's).
    tpm2_primary_alg: String,
    /// The PolicyPCR digest of the PCR values sealed to, hex.
    tpm2_policy_hash: String,
}

impl Token {
    fn new(sealed: &Sealed, policy: &[u8; 32]) -> Self {
        Self {
            kind: TOKEN_TYPE.into(),
            keyslots: vec![KEYSLOT.to_string()],
            tpm2_blob: BASE64.encode(sealed.to_blob()),
            tpm2_pcrs: PCRS.to_vec(),
            tpm2_pcr_bank: "sha256".into(),
            tpm2_primary_alg: "ecc".into(),
            tpm2_policy_hash: hex::encode(policy),
        }
    }

    /// The sealed key and the policy it was sealed to, if this token is one dust-init wrote.
    fn parse(&self) -> anyhow::Result<(Sealed, [u8; 32])> {
        ensure!(
            self.tpm2_pcrs == PCRS,
            "bound to PCRs {:?}, not {PCRS:?}",
            self.tpm2_pcrs
        );
        ensure!(self.tpm2_pcr_bank == "sha256", "PCR bank {}", self.tpm2_pcr_bank);
        ensure!(self.tpm2_primary_alg == "ecc", "primary key {}", self.tpm2_primary_alg);
        ensure!(self.keyslots == [KEYSLOT.to_string()], "keyslots {:?}", self.keyslots);
        let blob = BASE64.decode(&self.tpm2_blob).context("tpm2-blob")?;
        let sealed = Sealed::from_blob(&blob).context("tpm2-blob")?;
        let mut policy = [0; 32];
        hex::decode_to_slice(&self.tpm2_policy_hash, &mut policy).context("tpm2-policy-hash")?;
        Ok((sealed, policy))
    }

    /// dust-init's token among those of a LUKS2 header's JSON metadata.
    fn find(metadata: &[u8]) -> anyhow::Result<Option<Self>> {
        #[derive(Deserialize)]
        struct Metadata {
            #[serde(default)]
            tokens: std::collections::BTreeMap<String, serde_json::Value>,
        }
        let metadata: Metadata = serde_json::from_slice(metadata).context("parsing the LUKS2 metadata")?;
        let ours = (metadata.tokens.into_values()).find(|token| token["type"] == TOKEN_TYPE);
        ours.map(|token| serde_json::from_value(token).context("parsing the token"))
            .transpose()
    }
}

/// The effects of [`setup`], so that its decisions can be tested without a disk or a TPM.
trait Volume {
    fn content(&mut self) -> anyhow::Result<Content>;
    /// dust-init's token in the LUKS2 header.
    async fn token(&mut self) -> anyhow::Result<Option<Token>>;
    /// The policy of the current values of PCR 11.
    async fn policy(&mut self) -> Result<[u8; 32], TpmError>;
    async fn seal(&mut self, key: &Key, policy: [u8; 32]) -> Result<Sealed, TpmError>;
    async fn unseal(&mut self, sealed: &Sealed) -> Result<Key, TpmError>;
    /// Formats the partition as LUKS2, `key` opening its keyslot, with `token`.
    async fn format(&mut self, key: &Key, token: &Token) -> anyhow::Result<()>;
    /// Opens it as [`MAPPED`]; `false` when `key` opens no keyslot.
    async fn open(&mut self, key: &Key) -> anyhow::Result<bool>;
    /// Whether [`MAPPED`] holds a filesystem.
    fn has_filesystem(&mut self) -> anyhow::Result<bool>;
    /// Creates the filesystem of [`MAPPED`].
    async fn mkfs(&mut self) -> anyhow::Result<()>;
}

/// The state partition, with the TPM and the programs that set it up.
struct Partition<'a> {
    reaper: &'a Reaper,
    device: &'a Path,
    /// Taken by the blocking task using it.
    tpm: Option<Tpm>,
}

impl<'a> Partition<'a> {
    /// Runs `f` on the TPM, in a blocking task.
    async fn with_tpm<T: Send + 'static>(
        &mut self,
        f: impl FnOnce(&mut Tpm) -> Result<T, TpmError> + Send + 'static,
    ) -> Result<T, TpmError> {
        let mut tpm = self.tpm.take().ok_or(TpmError::Malformed("the TPM was lost"))?;
        let (tpm, result) = tokio::task::spawn_blocking(move || {
            let result = f(&mut tpm);
            (tpm, result)
        })
        .await
        .map_err(|e| TpmError::Io(std::io::Error::other(e)))?;
        self.tpm = Some(tpm);
        result
    }

    /// Runs `program` with `args`, `input` on its standard input, and returns its exit status and
    /// standard output. Its errors are logged when it fails.
    async fn run(&self, program: &str, args: &[&str], input: &[u8]) -> anyhow::Result<(Exit, Vec<u8>)> {
        let mut command = Command::new(program);
        command.args(args).env_clear().current_dir("/");
        let output = (self.reaper.output(&mut command, input).await)
            .with_context(|| format!("running {program} {}", args[0]))?;
        if output.exit != Exit::Code(0) {
            for line in String::from_utf8_lossy(&output.stderr).lines() {
                warn!("{program}: {line}");
            }
        }
        Ok((output.exit, output.stdout))
    }

    /// Runs `program` with `args`, failing unless it succeeds.
    async fn run_ok(&self, program: &str, args: &[&str], input: &[u8]) -> anyhow::Result<Vec<u8>> {
        match self.run(program, args, input).await? {
            (Exit::Code(0), stdout) => Ok(stdout),
            (exit, _) => bail!("{program} {} failed with {exit}", args[0]),
        }
    }

    fn device(&self) -> anyhow::Result<&'a str> {
        (self.device.to_str()).with_context(|| format!("{} is not UTF-8", self.device.display()))
    }
}

impl Volume for Partition<'_> {
    fn content(&mut self) -> anyhow::Result<Content> {
        Content::probe(self.device)
    }

    async fn token(&mut self) -> anyhow::Result<Option<Token>> {
        let args = ["luksDump", "--dump-json-metadata", self.device()?];
        Token::find(&self.run_ok(CRYPTSETUP, &args, &[]).await?)
    }

    async fn policy(&mut self) -> Result<[u8; 32], TpmError> {
        self.with_tpm(|tpm| tpm.pcr_policy(&PCRS)).await
    }

    async fn seal(&mut self, key: &Key, policy: [u8; 32]) -> Result<Sealed, TpmError> {
        let key = key.clone();
        self.with_tpm(move |tpm| tpm.seal(&key, &policy)).await
    }

    async fn unseal(&mut self, sealed: &Sealed) -> Result<Key, TpmError> {
        let sealed = sealed.clone();
        self.with_tpm(move |tpm| tpm.unseal(&sealed, &PCRS)).await
    }

    async fn format(&mut self, key: &Key, token: &Token) -> anyhow::Result<()> {
        let device = self.device()?;
        let keyslot = KEYSLOT.to_string();
        let keyslot = keyslot.as_str();
        // The key is random: a slow PBKDF would add nothing (cryptsetup's minimum for PBKDF2).
        #[rustfmt::skip]
        let args = [
            "luksFormat", "--batch-mode", "--type", "luks2",
            "--cipher", "aes-xts-plain64", "--key-size", "512", "--sector-size", "4096",
            "--hash", "sha256", "--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000",
            "--label", "hardened-state", "--key-slot", keyslot, "--key-file", "-", device,
        ];
        self.run_ok(CRYPTSETUP, &args, key).await?;
        let token = serde_json::to_vec(token)?;
        let args = ["token", "import", "--token-id", keyslot, "--json-file", "-", device];
        self.run_ok(CRYPTSETUP, &args, &token).await?;
        Ok(())
    }

    async fn open(&mut self, key: &Key) -> anyhow::Result<bool> {
        let keyslot = KEYSLOT.to_string();
        #[rustfmt::skip]
        let args = [
            "open", "--type", "luks2", "--key-slot", keyslot.as_str(), "--key-file", "-",
            self.device()?, MAPPING,
        ];
        match self.run(CRYPTSETUP, &args, key).await? {
            (Exit::Code(0), _) => {}
            // No keyslot opens with this key.
            (Exit::Code(2), _) => return Ok(false),
            (exit, _) => bail!("{CRYPTSETUP} open failed with {exit}"),
        }
        // libdevmapper creates the node itself (there is no udev).
        ensure!(Path::new(MAPPED).exists(), "{MAPPED} did not appear");
        Ok(true)
    }

    fn has_filesystem(&mut self) -> anyhow::Result<bool> {
        Ok(Content::probe(Path::new(MAPPED))? == Content::Ext4)
    }

    async fn mkfs(&mut self) -> anyhow::Result<()> {
        // As the image's: 4 KiB blocks (one per encryption sector), 64-bit, labelled STATE. No
        // discard: dm-crypt does not pass discards through, and they would reveal what is used.
        #[rustfmt::skip]
        let args = [
            "-q", "-F", "-t", "ext4", "-b", "4096", "-O", "64bit", "-L", "STATE",
            "-E", "nodiscard,root_owner=0:0", MAPPED,
        ];
        self.run_ok(MKE2FS, &args, &[]).await?;
        info!("state filesystem created");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::attestation::ResponseCode;

    fn tpm_response(rc: u32) -> TpmError {
        TpmError::Response(ResponseCode(rc))
    }

    #[test]
    fn probes_the_partition_contents() {
        let mut head = vec![0; Content::PROBED];
        assert_eq!(Content::of(&head), Content::Other);
        head[1080..1082].copy_from_slice(&[0x53, 0xEF]);
        assert_eq!(Content::of(&head), Content::Ext4);
        head[..8].copy_from_slice(b"LUKS\xba\xbe\x00\x02");
        assert_eq!(Content::of(&head), Content::Luks2);
        head[..8].copy_from_slice(b"LUKS\xba\xbe\x00\x01");
        assert_eq!(Content::of(&head), Content::Ext4, "LUKS1 is not ours");
        assert_eq!(Content::of(b"LUKS\xba\xbe"), Content::Other);
    }

    fn sealed() -> Sealed {
        Sealed {
            private: vec![1, 2, 3],
            public: vec![4, 5],
        }
    }

    const POLICY: [u8; 32] = [0xAA; 32];

    #[test]
    fn token_round_trips_through_the_luks2_metadata() {
        let token = Token::new(&sealed(), &POLICY);
        let json = serde_json::to_value(&token).unwrap();
        assert_eq!(json["type"], "hardened-tpm2");
        assert_eq!(json["keyslots"], serde_json::json!(["0"]));
        assert_eq!(json["tpm2-blob"], "AAMBAgMAAgQF");
        assert_eq!(json["tpm2-pcrs"], serde_json::json!([11]));
        assert_eq!(json["tpm2-policy-hash"], "aa".repeat(32));

        let metadata = serde_json::json!({
            "keyslots": {},
            "tokens": {
                "0": { "type": "systemd-recovery", "keyslots": ["1"] },
                "1": json,
            },
        });
        let found = Token::find(&serde_json::to_vec(&metadata).unwrap()).unwrap();
        assert_eq!(found.as_ref(), Some(&token));
        assert_eq!(found.unwrap().parse().unwrap(), (sealed(), POLICY));
        assert_eq!(Token::find(br#"{"tokens": {}}"#).unwrap(), None);
        assert_eq!(Token::find(br#"{"keyslots": {}}"#).unwrap(), None);
        assert!(Token::find(b"not json").is_err());
    }

    /// `cryptsetup luksDump --dump-json-metadata` of a volume formatted and given a token as
    /// dust-init does.
    #[test]
    fn finds_the_token_in_cryptsetup_output() {
        let dump = br#"{
  "keyslots":{"0":{"type":"luks2","key_size":64,"af":{"type":"luks1","stripes":4000,"hash":"sha256"},
    "area":{"type":"raw","offset":"32768","size":"258048","encryption":"aes-xts-plain64","key_size":64},
    "kdf":{"type":"pbkdf2","hash":"sha256","iterations":1000,"salt":"2Lmy1zkv+B79BU3ofy3kpLxK7LxisITzu8l+uuvWQUk="}}},
  "tokens":{"0":{"type":"hardened-tpm2","keyslots":["0"],"tpm2-blob":"AAMBAgMAAgQF","tpm2-pcrs":[11],
    "tpm2-pcr-bank":"sha256","tpm2-primary-alg":"ecc",
    "tpm2-policy-hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
  "segments":{"0":{"type":"crypt","offset":"16777216","size":"dynamic","iv_tweak":"0",
    "encryption":"aes-xts-plain64","sector_size":4096}},
  "digests":{"0":{"type":"pbkdf2","keyslots":["0"],"segments":["0"],"hash":"sha256","iterations":1000,
    "salt":"F31p9rLN0OOdLYVWk8QkWzx4E++EfqpbBpvrkAT+FRE=","digest":"L/6a+/AoypTBD9QLBIjRSYSHXJmvjNq9BspcWhA6EMM="}},
  "config":{"json_size":"12288","keyslots_size":"16744448"}
}"#;
        let token = Token::find(dump).unwrap().unwrap();
        assert_eq!(token, Token::new(&sealed(), &POLICY));
    }

    #[test]
    fn rejects_tokens_it_did_not_write() {
        let token = Token::new(&sealed(), &POLICY);
        for broken in [
            Token {
                tpm2_pcrs: vec![7, 11],
                ..token.clone()
            },
            Token {
                tpm2_pcr_bank: "sha1".into(),
                ..token.clone()
            },
            Token {
                tpm2_blob: "AAMBAg==".into(),
                ..token.clone()
            },
            Token {
                tpm2_policy_hash: "aa".into(),
                ..token.clone()
            },
        ] {
            assert!(broken.parse().is_err(), "{broken:?}");
        }
    }

    /// A partition and a TPM in memory, recording what was done.
    #[derive(Default)]
    struct Fake {
        content: Option<Content>,
        token: Option<Token>,
        /// The current PCR 11 policy.
        policy: [u8; 32],
        /// What the TPM answers to Unseal (the key when `None`).
        unseal_error: Option<u32>,
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

        async fn token(&mut self) -> anyhow::Result<Option<Token>> {
            Ok(self.token.clone())
        }

        async fn policy(&mut self) -> Result<[u8; 32], TpmError> {
            Ok(self.policy)
        }

        async fn seal(&mut self, key: &Key, policy: [u8; 32]) -> Result<Sealed, TpmError> {
            self.log.push("seal");
            Ok(Sealed {
                private: key.to_vec(),
                public: policy.to_vec(),
            })
        }

        async fn unseal(&mut self, sealed: &Sealed) -> Result<Key, TpmError> {
            self.log.push("unseal");
            match self.unseal_error {
                Some(rc) => Err(tpm_response(rc)),
                None if sealed.public == self.policy => Ok(Zeroizing::new(sealed.private.clone())),
                None => Err(tpm_response(0x99D)),
            }
        }

        async fn format(&mut self, key: &Key, token: &Token) -> anyhow::Result<()> {
            self.log.push("format");
            self.content = Some(Content::Luks2);
            self.token = Some(token.clone());
            self.keyslot = Some(key.to_vec());
            self.filesystem = false;
            Ok(())
        }

        async fn open(&mut self, key: &Key) -> anyhow::Result<bool> {
            self.log.push("open");
            ensure!(!self.fail_open, "device-mapper error");
            Ok(self.keyslot.as_deref() == Some(&key[..]))
        }

        fn has_filesystem(&mut self) -> anyhow::Result<bool> {
            Ok(self.filesystem)
        }

        async fn mkfs(&mut self) -> anyhow::Result<()> {
            self.log.push("mkfs");
            self.filesystem = true;
            Ok(())
        }
    }

    /// A fake whose partition was formatted on a boot with `policy`.
    async fn formatted(policy: [u8; 32]) -> Fake {
        let mut fake = Fake {
            content: Some(Content::Ext4),
            policy,
            ..Fake::default()
        };
        assert_eq!(
            formatted_because(&mut fake).await,
            "it was not encrypted (first boot with encryption)"
        );
        fake.log.clear();
        fake
    }

    /// Runs [`setup`], expecting it to format: why it did.
    async fn formatted_because(fake: &mut Fake) -> String {
        match setup(fake).await.unwrap() {
            Outcome::Formatted(reason) => reason,
            Outcome::Unlocked => panic!("unlocked"),
        }
    }

    #[tokio::test]
    async fn first_boot_formats_then_later_boots_unlock() {
        let mut fake = formatted(POLICY).await;
        assert!(fake.filesystem);
        assert_eq!(fake.keyslot.as_ref().map(Vec::len), Some(KEY_LEN));

        assert_eq!(setup(&mut fake).await.unwrap(), Outcome::Unlocked);
        assert_eq!(fake.log, ["unseal", "open"]);
    }

    #[tokio::test]
    async fn seals_before_touching_the_disk() {
        let mut fake = Fake {
            content: Some(Content::Other),
            ..Fake::default()
        };
        assert_eq!(formatted_because(&mut fake).await, "it held no known format");
        assert_eq!(fake.log, ["seal", "format", "open", "mkfs"]);
    }

    #[tokio::test]
    async fn another_image_reformats() {
        let mut fake = formatted(POLICY).await;
        let old_key = fake.keyslot.clone();
        fake.policy = [0xBB; 32];
        assert_eq!(
            formatted_because(&mut fake).await,
            "it could not be unlocked: its key is sealed to another image (PCR 11 differs)"
        );
        assert_eq!(fake.log, ["seal", "format", "open", "mkfs"], "no unseal attempt");
        assert_ne!(fake.keyslot, old_key);

        // The new key is sealed to the new image.
        fake.log.clear();
        assert_eq!(setup(&mut fake).await.unwrap(), Outcome::Unlocked);
    }

    #[tokio::test]
    async fn a_tpm_that_cannot_unseal_reformats() {
        for rc in [0x99D, 0x1DF] {
            let mut fake = formatted(POLICY).await;
            fake.unseal_error = Some(rc);
            let reason = formatted_because(&mut fake).await;
            assert!(reason.contains("the TPM cannot unseal its key"), "{rc:#x}: {reason}");
        }
    }

    #[tokio::test]
    async fn unexpected_failures_leave_the_partition_alone() {
        // A TPM error that says nothing about the key (out of memory, lockout).
        for rc in [0x902, 0x921] {
            let mut fake = formatted(POLICY).await;
            fake.unseal_error = Some(rc);
            assert!(setup(&mut fake).await.is_err(), "{rc:#x}");
            assert_eq!(fake.log, ["unseal"]);
        }
        let mut fake = formatted(POLICY).await;
        fake.fail_open = true;
        assert!(setup(&mut fake).await.is_err());
        assert!(!fake.log.contains(&"format"));
        let mut fake = Fake::default();
        assert!(setup(&mut fake).await.is_err(), "unreadable partition");
        assert!(fake.log.is_empty());
    }

    #[tokio::test]
    async fn luks2_without_a_usable_token_reformats() {
        let mut fake = formatted(POLICY).await;
        fake.token = None;
        assert!(formatted_because(&mut fake).await.contains("no hardened-tpm2 token"));

        let mut fake = formatted(POLICY).await;
        fake.token.as_mut().unwrap().tpm2_pcrs = vec![7];
        assert!(formatted_because(&mut fake).await.contains("token is unusable"));

        // The token's key does not open the keyslot.
        let mut fake = formatted(POLICY).await;
        fake.keyslot = Some(vec![0; KEY_LEN]);
        assert!(
            formatted_because(&mut fake)
                .await
                .contains("opens none of its keyslots")
        );
        assert_eq!(fake.log, ["unseal", "open", "seal", "format", "open", "mkfs"]);
    }

    #[tokio::test]
    async fn an_interrupted_first_boot_creates_the_filesystem() {
        let mut fake = formatted(POLICY).await;
        fake.filesystem = false;
        assert_eq!(setup(&mut fake).await.unwrap(), Outcome::Unlocked);
        assert_eq!(fake.log, ["unseal", "open", "mkfs"]);
    }
}

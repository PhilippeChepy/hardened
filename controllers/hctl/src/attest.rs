//! Remote attestation evidence.

use std::io::{self, Write as _};

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context as _, anyhow, bail, ensure};
use clap::{Args, Subcommand, ValueEnum};
use ring::rand::{SecureRandom as _, SystemRandom};
use serde::{Deserialize, Serialize};
use tonic::transport::Channel;
use trust_controller::attestation::attestation_client::AttestationClient;
use trust_controller::attestation::{HashAlgorithm, PcrValue, PcrsRequest, QuoteRequest};
use trust_controller::quote_verification;

use crate::args::Nonce;
use crate::client::CallExt;
use crate::endorsement;
use crate::endorsement::EkType;

/// Event logs can exceed tonic's 4 MiB default.
const MAX_MESSAGE_SIZE: usize = 64 << 20;

/// The `hctl attest` subcommands.
#[derive(Subcommand)]
pub enum Command {
    /// Reads PCR values.
    Pcrs(Selection),
    /// Requests a TPM2 quote over PCRs, printed as JSON with hex fields.
    Quote {
        /// Verifier-chosen freshness nonce, hex (1 to 64 bytes).
        #[arg(long)]
        nonce: Nonce,
        #[command(flatten)]
        selection: Selection,
    },
    /// Shows the TPM's endorsement key (EK): its fingerprint, to pin with `verify --ek`, and
    /// whether the TPM holds its certificate.
    Ek {
        #[arg(long, value_enum, default_value_t = EkType::Rsa)]
        ek_type: EkType,
        /// Writes the EK certificate (DER) to FILE.
        #[arg(long, value_name = "FILE")]
        certificate: Option<PathBuf>,
    },
    /// Verifies the machine: its endorsement key (certified or pinned), its attestation key (in
    /// the same TPM, by credential activation), then a fresh quote of its PCRs (signature,
    /// nonce, PCR digest) against the values expected.
    Verify {
        /// The expected PCR values, as the build writes them (`build/out/<image>.pcrs.json`).
        #[arg(long, value_name = "FILE")]
        expected: PathBuf,
        #[arg(long, value_enum, default_value_t = EkType::Rsa)]
        ek_type: EkType,
        /// Certificates (PEM or DER) one of which must issue the TPM's EK certificate: the
        /// TPM's manufacturer's, or the cloud's for a vTPM.
        #[arg(
            long,
            value_name = "FILE",
            conflicts_with = "ek",
            required_unless_present = "ek"
        )]
        ek_ca: Option<PathBuf>,
        /// The EK's fingerprint (`hctl attest ek`), for TPMs without an EK certificate.
        #[arg(long, value_name = "FINGERPRINT")]
        ek: Option<String>,
        /// The attestation key's fingerprint (SHA-256 of its TPMT_PUBLIC, hex) to require too.
        #[arg(long, value_name = "FINGERPRINT")]
        ak: Option<String>,
    },
    /// Writes the raw TCG event log to stdout.
    #[command(name = "eventlog")]
    EventLog,
}

/// The PCRs a command reads.
#[derive(Args)]
pub struct Selection {
    /// PCR bank.
    #[arg(long, value_enum, default_value_t = Bank::Sha256)]
    bank: Bank,
    /// Comma-separated PCR indexes [default: 0-23].
    #[arg(
        long = "pcr",
        value_delimiter = ',',
        value_parser = clap::value_parser!(u32).range(0..24)
    )]
    pcrs: Vec<u32>,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Bank {
    Sha1,
    Sha256,
    Sha384,
}

impl From<Bank> for HashAlgorithm {
    fn from(bank: Bank) -> Self {
        match bank {
            Bank::Sha1 => Self::Sha1,
            Bank::Sha256 => Self::Sha256,
            Bank::Sha384 => Self::Sha384,
        }
    }
}

#[must_use]
fn bank_name(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 | HashAlgorithm::Unspecified => "sha256",
        HashAlgorithm::Sha384 => "sha384",
    }
}

/// `hctl attest verify --expected`'s file: PCR values by bank, then index, hex.
type Expected = BTreeMap<Bank, BTreeMap<u32, String>>;

/// `hctl attest quote`'s output.
#[derive(Serialize)]
struct Quote {
    nonce: String,
    bank: &'static str,
    attest: String,
    signature: String,
    ak_public: String,
    pcrs: Vec<Pcr>,
}

#[derive(Serialize)]
struct Pcr {
    index: u32,
    digest: String,
}

impl From<PcrValue> for Pcr {
    fn from(value: PcrValue) -> Self {
        Self {
            index: value.index,
            digest: hex::encode(value.digest),
        }
    }
}

/// Runs an `hctl attest` subcommand on `channel`.
pub async fn run(channel: Channel, command: Command) -> anyhow::Result<()> {
    use std::io::IsTerminal as _;

    let mut client = AttestationClient::new(channel).max_decoding_message_size(MAX_MESSAGE_SIZE);
    let mut out = io::stdout().lock();
    match command {
        Command::Pcrs(Selection { bank, pcrs }) => {
            let mut request = PcrsRequest {
                pcrs,
                ..Default::default()
            };
            request.set_bank(bank.into());
            let response = client.pcrs(request).await.into_result()?;
            writeln!(out, "{}:", bank_name(response.bank()))?;
            for value in response.values {
                writeln!(out, "  {:>2}: {}", value.index, hex::encode(value.digest))?;
            }
        }
        Command::Quote {
            nonce,
            selection: Selection { bank, pcrs },
        } => {
            let mut request = QuoteRequest {
                nonce: nonce.as_bytes().to_vec(),
                pcrs,
                ..Default::default()
            };
            request.set_bank(bank.into());
            let response = client.quote(request).await.into_result()?;
            let quote = Quote {
                nonce: hex::encode(nonce.as_bytes()),
                bank: bank_name(bank.into()),
                attest: hex::encode(response.attest),
                signature: hex::encode(response.signature),
                ak_public: hex::encode(response.ak_public),
                pcrs: response.values.into_iter().map(Pcr::from).collect(),
            };
            serde_json::to_writer_pretty(&mut out, &quote)?;
            writeln!(out)?;
        }
        Command::Ek {
            ek_type,
            certificate,
        } => {
            let endorsement = endorsement::fetch(&mut client, ek_type).await?;
            writeln!(
                out,
                "fingerprint: {}",
                endorsement::fingerprint(&endorsement.ek_public)
            )?;
            if endorsement.certificate.is_empty() {
                writeln!(out, "certificate: none")?;
            } else {
                writeln!(out, "certificate: {} bytes", endorsement.certificate.len())?;
                if let Some(path) = certificate {
                    fs::write(&path, &endorsement.certificate)
                        .with_context(|| path.display().to_string())?;
                }
            }
        }
        Command::Verify {
            expected,
            ek_type,
            ek_ca,
            ek,
            ak,
        } => {
            let trust = match (&ek_ca, &ek) {
                (Some(file), _) => endorsement::Trust::Ca(file),
                (None, Some(pinned)) => endorsement::Trust::Pinned(pinned),
                (None, None) => unreachable!("clap requires --ek-ca or --ek"),
            };
            let endorsement = endorsement::fetch(&mut client, ek_type).await?;
            let (ek, trusted) = endorsement::trusted(&endorsement, &trust)?;
            writeln!(out, "endorsement key: {trusted}")?;
            endorsement::prove_attestation_key(&mut client, ek_type, &ek, &endorsement).await?;
            writeln!(
                out,
                "attestation key: {} (in the EK's TPM: credential activated)",
                endorsement::fingerprint(&endorsement.ak_public)
            )?;
            let expected: Expected = serde_json::from_slice(
                &fs::read(&expected).with_context(|| expected.display().to_string())?,
            )
            .with_context(|| format!("parsing {}", expected.display()))?;
            let mut banks = expected.into_iter();
            let (Some((bank, pcrs)), None) = (banks.next(), banks.next()) else {
                bail!("the expected values must be of one bank");
            };
            let mut nonce = [0; 32];
            SystemRandom::new()
                .fill(&mut nonce)
                .map_err(|_| anyhow!("no randomness for the nonce"))?;
            let mut request = QuoteRequest {
                nonce: nonce.to_vec(),
                pcrs: pcrs.keys().copied().collect(),
                ..Default::default()
            };
            request.set_bank(bank.into());
            let quote = client.quote(request).await.into_result()?;
            ensure!(
                quote.ak_public == endorsement.ak_public,
                "the quote is signed by another attestation key than the EK's TPM proved"
            );
            let verified = quote_verification::verify(&quote, &nonce, bank.into())
                .context("the quote is not valid")?;
            writeln!(out, "quote: valid (signature, fresh nonce, PCR digest)")?;
            let mut mismatches = 0;
            for (index, digest) in &pcrs {
                let actual = verified
                    .pcrs
                    .get(index)
                    .map(hex::encode)
                    .unwrap_or_default();
                if actual == digest.to_lowercase() {
                    writeln!(out, "PCR {index}: {actual} (expected)")?;
                } else {
                    writeln!(out, "PCR {index}: {actual}, expected {digest}")?;
                    mismatches += 1;
                }
            }
            let fingerprint = endorsement::fingerprint(&quote.ak_public);
            if let Some(pinned) = ak
                && pinned.to_lowercase() != fingerprint
            {
                writeln!(out, "attestation key: {fingerprint}, expected {pinned}")?;
                mismatches += 1;
            }
            out.flush()?;
            if mismatches > 0 {
                bail!("the machine does not match: {mismatches} mismatch(es)");
            }
        }
        Command::EventLog => {
            if out.is_terminal() {
                bail!("the event log is binary: redirect stdout to a file");
            }
            let response = client.event_log(()).await.into_result()?;
            out.write_all(&response.event_log)?;
        }
    }
    out.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_values_the_build_expects() {
        let expected: Expected = serde_json::from_str(r#"{ "sha256": { "11": "AB" } }"#).unwrap();
        assert_eq!(expected[&Bank::Sha256][&11], "AB");
        assert!(serde_json::from_str::<Expected>(r#"{ "md5": { "11": "ab" } }"#).is_err());
    }
}

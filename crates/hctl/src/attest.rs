//! Remote attestation evidence.

use std::io::{self, IsTerminal, Write};

use anyhow::bail;
use clap::{Args, Subcommand, ValueEnum};
use dust_proto::v1::attestation_client::AttestationClient;
use dust_proto::v1::{HashAlgorithm, PcrValue, PcrsRequest, QuoteRequest};
use serde::Serialize;
use tonic::transport::Channel;

use crate::args::Nonce;
use crate::client::CallExt;

/// Event logs can exceed tonic's 4 MiB default.
const MAX_MESSAGE_SIZE: usize = 64 << 20;

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
    /// Writes the raw TCG event log to stdout.
    #[command(name = "eventlog")]
    EventLog,
}

#[derive(Args)]
pub struct Selection {
    /// PCR bank.
    #[arg(long, value_enum, default_value_t = Bank::Sha256)]
    bank: Bank,
    /// Comma-separated PCR indexes [default: 0-23].
    #[arg(long = "pcr", value_delimiter = ',', value_parser = clap::value_parser!(u32).range(0..24))]
    pcrs: Vec<u32>,
}

#[derive(Clone, Copy, ValueEnum)]
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

fn bank_name(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha1 => "sha1",
        HashAlgorithm::Sha256 | HashAlgorithm::Unspecified => "sha256",
        HashAlgorithm::Sha384 => "sha384",
    }
}

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

pub async fn run(channel: Channel, command: Command) -> anyhow::Result<()> {
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

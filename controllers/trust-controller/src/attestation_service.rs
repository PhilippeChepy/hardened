//! The `Attestation` service, on the TPM.

use std::io;

use tonic::Request;
use tonic::Response;
use tonic::Status;
use trust_controller::attestation::EventLogResponse;
use trust_controller::attestation::HashAlgorithm;
use trust_controller::attestation::PcrValue;
use trust_controller::attestation::PcrsRequest;
use trust_controller::attestation::PcrsResponse;
use trust_controller::attestation::QuoteRequest;
use trust_controller::attestation::QuoteResponse;
use trust_controller::attestation::attestation_server::Attestation;

use crate::access;
use crate::hash_alg::HashAlg;
use crate::shared_tpm::SharedTpm;
use crate::tpm;

/// The TCG event log of the boot (firmware and systemd-stub measurements), exported by the
/// kernel through securityfs, which a verifier replays against the quoted PCRs.
const EVENT_LOG: &str = "/sys/kernel/security/tpm0/binary_bios_measurements";
/// The only caller: machine-controller serves the evidence to verifiers, through
/// machine-apiproxy.
const CALLER: &str = "machine-controller";

/// Serves the `Attestation` service from a TPM.
pub struct AttestationService {
    tpm: SharedTpm,
}

impl AttestationService {
    /// Serves the evidence of `tpm`.
    #[must_use]
    pub fn new(tpm: SharedTpm) -> Self {
        Self { tpm }
    }
}

#[tonic::async_trait]
impl Attestation for AttestationService {
    async fn pcrs(&self, request: Request<PcrsRequest>) -> Result<Response<PcrsResponse>, Status> {
        access::require(&request, CALLER)?;
        let request = request.into_inner();
        let bank = tpm_hash_algorithm(request.bank)?;
        let pcrs = pcr_selection(request.pcrs);
        let values = self.tpm.run(move |tpm| tpm.pcr_read(bank, &pcrs)).await??;
        Ok(Response::new(PcrsResponse {
            bank: proto_hash_algorithm(bank).into(),
            values: pcr_values(values),
        }))
    }

    async fn event_log(&self, request: Request<()>) -> Result<Response<EventLogResponse>, Status> {
        access::require(&request, CALLER)?;
        let event_log = tokio::fs::read(EVENT_LOG)
            .await
            .map_err(|e| match e.kind() {
                io::ErrorKind::NotFound => {
                    Status::failed_precondition("this machine has no TPM event log")
                }
                _ => Status::internal(format!("reading {EVENT_LOG}: {e}")),
            })?;
        Ok(Response::new(EventLogResponse { event_log }))
    }

    async fn quote(
        &self,
        request: Request<QuoteRequest>,
    ) -> Result<Response<QuoteResponse>, Status> {
        access::require(&request, CALLER)?;
        let request = request.into_inner();
        let bank = tpm_hash_algorithm(request.bank)?;
        let pcrs = pcr_selection(request.pcrs);
        let nonce = request.nonce;
        // Tpm::quote checks the nonce's length, and that the quote is over the values it returns.
        let quote = self
            .tpm
            .run(move |tpm| tpm.quote(&nonce, bank, &pcrs))
            .await??;
        Ok(Response::new(QuoteResponse {
            attest: quote.attest,
            signature: quote.signature,
            ak_public: quote.ak_public,
            values: pcr_values(quote.pcrs),
        }))
    }
}

/// The PCR bank a request names; SHA-256 when it names none.
fn tpm_hash_algorithm(bank: i32) -> Result<HashAlg, Status> {
    match HashAlgorithm::try_from(bank) {
        Ok(HashAlgorithm::Unspecified | HashAlgorithm::Sha256) => Ok(HashAlg::Sha256),
        Ok(HashAlgorithm::Sha1) => Ok(HashAlg::Sha1),
        Ok(HashAlgorithm::Sha384) => Ok(HashAlg::Sha384),
        Err(_) => Err(Status::invalid_argument(format!(
            "unknown hash algorithm {bank}"
        ))),
    }
}

#[must_use]
fn proto_hash_algorithm(bank: HashAlg) -> HashAlgorithm {
    match bank {
        HashAlg::Sha1 => HashAlgorithm::Sha1,
        HashAlg::Sha256 => HashAlgorithm::Sha256,
        HashAlg::Sha384 => HashAlgorithm::Sha384,
    }
}

/// The PCRs a request selects: all of them when it selects none.
#[must_use]
fn pcr_selection(pcrs: Vec<u32>) -> Vec<u32> {
    if pcrs.is_empty() {
        (0..tpm::PCR_COUNT).collect()
    } else {
        pcrs
    }
}

#[must_use]
fn pcr_values(values: Vec<(u32, Vec<u8>)>) -> Vec<PcrValue> {
    values
        .into_iter()
        .map(|(index, digest)| PcrValue { index, digest })
        .collect()
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::*;
    use crate::access::from;
    use crate::tpm::Tpm;
    use crate::transport::Unplugged;

    #[test]
    fn hash_algorithms_default_to_sha256() {
        assert_eq!(tpm_hash_algorithm(0).unwrap(), HashAlg::Sha256);
        assert_eq!(tpm_hash_algorithm(1).unwrap(), HashAlg::Sha1);
        assert_eq!(tpm_hash_algorithm(3).unwrap(), HashAlg::Sha384);
        assert!(tpm_hash_algorithm(9).is_err());
        assert_eq!(pcr_selection(Vec::new()).len(), 24);
        assert_eq!(pcr_selection(vec![7]), [7]);
    }

    fn service() -> AttestationService {
        AttestationService::new(SharedTpm::new(Tpm::with_transport(Unplugged)))
    }

    #[tokio::test]
    async fn validates_requests_before_the_tpm() {
        let service = service();
        let unknown_bank = PcrsRequest {
            bank: 9,
            pcrs: vec![],
        };
        let status = service.pcrs(from(CALLER, unknown_bank)).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument);

        let status = service
            .pcrs(from(CALLER, PcrsRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::Internal, "{status:?}");
        assert!(status.message().contains("unplugged"), "{status:?}");

        let long_nonce = QuoteRequest {
            nonce: vec![0; 65],
            ..Default::default()
        };
        let status = service.quote(from(CALLER, long_nonce)).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
    }

    #[tokio::test]
    async fn serves_machine_controller_only() {
        let service = service();
        for caller in ["storage-controller", "machine-apiproxy"] {
            let status = service
                .pcrs(from(caller, PcrsRequest::default()))
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{caller}");
            let status = service.event_log(from(caller, ())).await.unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{caller}");
            let status = service
                .quote(from(caller, QuoteRequest::default()))
                .await
                .unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{caller}");
        }
        let status = service
            .pcrs(Request::new(PcrsRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied, "without a caller");
    }
}

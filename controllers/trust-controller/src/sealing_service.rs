//! The `Sealing` service: secrets only the TPM, booting this image, unseals.

use bytes::Bytes;
use tonic::Request;
use tonic::Response;
use tonic::Status;
use trust_controller::trust::SealedSecret;
use trust_controller::trust::Secret;
use trust_controller::trust::sealing_server::Sealing;
use zeroize::Zeroizing;

use crate::access;
use crate::sealed_object;
use crate::sealed_object::SealedObject;
use crate::shared_tpm::SharedTpm;
use crate::tpm_error::TpmError;

/// The only caller: storage-controller seals the state partition's key.
const CALLER: &str = "storage-controller";
/// MAX_SYM_DATA: the most a sealed data object holds.
const MAX_SECRET_LEN: usize = 128;

/// Serves the `Sealing` service from a TPM.
pub struct SealingService {
    tpm: SharedTpm,
}

impl SealingService {
    /// Seals with `tpm`.
    #[must_use]
    pub fn new(tpm: SharedTpm) -> Self {
        Self { tpm }
    }
}

#[tonic::async_trait]
impl Sealing for SealingService {
    async fn seal(&self, request: Request<Secret>) -> Result<Response<SealedSecret>, Status> {
        access::require(&request, CALLER)?;
        // A view of tonic's decode buffer, copied out to be wiped.
        let secret = Zeroizing::new(request.into_inner().secret.to_vec());
        if secret.is_empty() || secret.len() > MAX_SECRET_LEN {
            return Err(Status::invalid_argument(format!(
                "a secret of {} bytes, expected 1 to {MAX_SECRET_LEN}",
                secret.len()
            )));
        }
        let (sealed, policy) = self
            .tpm
            .run(move |tpm| {
                let policy = tpm.pcr_policy(&sealed_object::PCRS)?;
                let sealed = tpm.seal(&secret, &policy)?;
                Ok::<_, TpmError>((sealed, policy))
            })
            .await??;
        tracing::info!("sealed a secret to PCR 11");
        Ok(Response::new(SealedSecret {
            sealed: SealedObject::new(&sealed, &policy).encode(),
        }))
    }

    async fn unseal(&self, request: Request<SealedSecret>) -> Result<Response<Secret>, Status> {
        access::require(&request, CALLER)?;
        let (sealed, policy) = SealedObject::decode(&request.into_inner().sealed)
            .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
        // Checked first, to tell another image from another TPM.
        let unsealed = self
            .tpm
            .run(move |tpm| {
                if tpm.pcr_policy(&sealed_object::PCRS)? != policy {
                    return Ok(None);
                }
                tpm.unseal(&sealed, &sealed_object::PCRS).map(Some)
            })
            .await?;
        match unsealed {
            Ok(Some(secret)) => Ok(Response::new(Secret {
                // Moved, not copied, and wiped once tonic encoded and dropped the response.
                secret: Bytes::from_owner(secret),
            })),
            Ok(None) => Err(Status::failed_precondition(
                "sealed to another image (PCR 11 differs)",
            )),
            Err(e) if e.is_sealed_elsewhere() => Err(Status::failed_precondition(format!(
                "the TPM cannot unseal it (another or a cleared TPM): {e}"
            ))),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use tonic::Code;

    use super::*;
    use crate::access::from;
    use crate::sealed_object::Sealed;
    use crate::tpm::Tpm;
    use crate::transport::Unplugged;

    fn service() -> SealingService {
        SealingService::new(SharedTpm::new(Tpm::with_transport(Unplugged)))
    }

    fn secret() -> Secret {
        Secret {
            secret: Bytes::from(vec![7; 32]),
        }
    }

    fn sealed() -> SealedSecret {
        let sealed = Sealed {
            private: vec![1],
            public: vec![2],
        };
        SealedSecret {
            sealed: SealedObject::new(&sealed, &[0; 32]).encode(),
        }
    }

    #[tokio::test]
    async fn serves_storage_controller_only() {
        let service = service();
        for caller in ["machine-controller", "machine-apiproxy"] {
            let status = service.seal(from(caller, secret())).await.unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{caller}");
            let status = service.unseal(from(caller, sealed())).await.unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{caller}");
        }
        let status = service.seal(Request::new(secret())).await.unwrap_err();
        assert_eq!(status.code(), Code::PermissionDenied, "without a caller");

        // Let through, to the TPM.
        let status = service.seal(from(CALLER, secret())).await.unwrap_err();
        assert_eq!(status.code(), Code::Internal, "{status:?}");
        assert!(status.message().contains("unplugged"), "{status:?}");
        let status = service.unseal(from(CALLER, sealed())).await.unwrap_err();
        assert_eq!(status.code(), Code::Internal, "{status:?}");
    }

    #[tokio::test]
    async fn validates_requests_before_the_tpm() {
        let service = service();
        for length in [0, MAX_SECRET_LEN + 1] {
            let secret = Secret {
                secret: Bytes::from(vec![1; length]),
            };
            let status = service.seal(from(CALLER, secret)).await.unwrap_err();
            assert_eq!(status.code(), Code::InvalidArgument, "{length}");
        }
        let garbage = SealedSecret {
            sealed: b"{}".to_vec(),
        };
        let status = service.unseal(from(CALLER, garbage)).await.unwrap_err();
        assert_eq!(status.code(), Code::InvalidArgument, "{status:?}");
    }
}

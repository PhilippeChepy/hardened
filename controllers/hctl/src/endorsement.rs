//! The TPM's endorsement key (EK): trusted from its certificate or a pinned key, it proves the
//! attestation key is the same TPM's, by credential activation.

use std::fs;
use std::path::Path;

use anyhow::{Context as _, anyhow, bail, ensure};
use clap::ValueEnum;
use ring::digest;
use ring::rand::{SecureRandom as _, SystemRandom};
use tonic::transport::Channel;
use trust_controller::attestation::attestation_client::AttestationClient;
use trust_controller::attestation::{
    ActivateCredentialRequest, EndorsementKeyRequest, EndorsementKeyResponse, EndorsementKeyType,
};
use trust_controller::credential;
use trust_controller::credential::EndorsementKey;
use x509_parser::certificate::X509Certificate;
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer as _;
use x509_parser::public_key::PublicKey;

use crate::client::CallExt;

/// `--ek-type`.
#[derive(Clone, Copy, ValueEnum)]
pub enum EkType {
    /// RSA 2048, the EK most TPMs certify.
    Rsa,
    /// ECC NIST P-256.
    Ecc,
}

impl From<EkType> for EndorsementKeyType {
    fn from(kind: EkType) -> Self {
        match kind {
            EkType::Rsa => Self::Rsa2048,
            EkType::Ecc => Self::EccP256,
        }
    }
}

/// The SHA-256 of a TPMT_PUBLIC, hex: how keys are pinned.
#[must_use]
pub fn fingerprint(public: &[u8]) -> String {
    hex::encode(digest::digest(&digest::SHA256, public))
}

/// The EK of `kind`, its certificate and the attestation key.
pub async fn fetch(
    client: &mut AttestationClient<Channel>,
    kind: EkType,
) -> anyhow::Result<EndorsementKeyResponse> {
    let mut request = EndorsementKeyRequest::default();
    request.set_type(kind.into());
    Ok(client.endorsement_key(request).await.into_result()?)
}

/// How the EK is trusted.
pub enum Trust<'a> {
    /// Its certificate must be issued by one of the certificates of this file (PEM or DER).
    Ca(&'a Path),
    /// Its fingerprint must be this one.
    Pinned(&'a str),
}

/// The EK of `endorsement`, if `trust` trusts it; with why.
pub fn trusted(
    endorsement: &EndorsementKeyResponse,
    trust: &Trust<'_>,
) -> anyhow::Result<(EndorsementKey, String)> {
    let ek = EndorsementKey::from_public(&endorsement.ek_public)?;
    let fingerprint = fingerprint(&endorsement.ek_public);
    match trust {
        Trust::Pinned(pinned) => {
            ensure!(
                pinned.to_lowercase() == fingerprint,
                "the endorsement key is {fingerprint}, not the pinned {pinned}"
            );
            Ok((ek, format!("{fingerprint} (pinned)")))
        }
        Trust::Ca(file) => {
            ensure!(
                !endorsement.certificate.is_empty(),
                "the TPM holds no EK certificate: pin its key with --ek {fingerprint}"
            );
            let issuer = certified(&endorsement.certificate, &ek, file)?;
            Ok((ek, format!("{fingerprint} (certified by {issuer})")))
        }
    }
}

/// The subject of the certificate of `ca_file` issuing `certificate` (DER), which must certify
/// `ek` and be valid now.
fn certified(certificate: &[u8], ek: &EndorsementKey, ca_file: &Path) -> anyhow::Result<String> {
    let (_, certificate) = X509Certificate::from_der(certificate)
        .map_err(|e| anyhow!("parsing the EK certificate: {e}"))?;
    ensure!(
        certificate.validity().is_valid(),
        "the EK certificate is not valid now"
    );
    ensure!(
        certifies(&certificate, ek)?,
        "the EK certificate is for another key"
    );
    let bytes = fs::read(ca_file).with_context(|| ca_file.display().to_string())?;
    let authorities: Vec<Vec<u8>> = if bytes.starts_with(b"-----") {
        Pem::iter_from_buffer(&bytes)
            .map(|pem| pem.map(|pem| pem.contents))
            .collect::<Result<_, _>>()
            .map_err(|e| anyhow!("parsing {}: {e}", ca_file.display()))?
    } else {
        vec![bytes]
    };
    for der in &authorities {
        let (_, authority) = X509Certificate::from_der(der)
            .map_err(|e| anyhow!("parsing {}: {e}", ca_file.display()))?;
        if authority.subject() == certificate.issuer()
            && certificate
                .verify_signature(Some(authority.public_key()))
                .is_ok()
        {
            return Ok(authority.subject().to_string());
        }
    }
    bail!(
        "the EK certificate, issued by {}, is not signed by a certificate of {}",
        certificate.issuer(),
        ca_file.display()
    )
}

/// Whether `certificate`'s public key is `ek`.
fn certifies(certificate: &X509Certificate<'_>, ek: &EndorsementKey) -> anyhow::Result<bool> {
    let key = certificate
        .public_key()
        .parsed()
        .map_err(|e| anyhow!("parsing the EK certificate's key: {e}"))?;
    Ok(match (key, ek) {
        (PublicKey::RSA(rsa), EndorsementKey::Rsa { modulus }) => {
            let strip = |bytes: &[u8]| -> Vec<u8> {
                bytes.iter().skip_while(|&&b| b == 0).copied().collect()
            };
            strip(rsa.modulus) == strip(modulus) && strip(rsa.exponent) == [0x01, 0x00, 0x01]
        }
        (PublicKey::EC(point), EndorsementKey::Ecc { x, y }) => {
            point.data() == [&[0x04][..], x, y].concat()
        }
        _ => false,
    })
}

/// Proves the attestation key of `endorsement` is in the TPM of its EK `ek`: a credential only
/// that TPM, holding both keys, can activate.
pub async fn prove_attestation_key(
    client: &mut AttestationClient<Channel>,
    kind: EkType,
    ek: &EndorsementKey,
    endorsement: &EndorsementKeyResponse,
) -> anyhow::Result<()> {
    let mut secret = [0; 32];
    SystemRandom::new()
        .fill(&mut secret)
        .map_err(|_| anyhow!("no randomness for the credential"))?;
    let made = credential::make(ek, &endorsement.ak_public, &secret)?;
    let mut request = ActivateCredentialRequest {
        credential_blob: made.blob,
        secret: made.secret,
        ..Default::default()
    };
    request.set_type(kind.into());
    let activated = client
        .activate_credential(request)
        .await
        .into_result()
        .context("activating the credential")?;
    ensure!(
        activated.credential == secret,
        "the TPM returned another secret: the attestation key is not its own"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair};

    use super::*;

    /// A CA (PEM), and a certificate it issues for an ECC P-256 EK (DER) with that EK.
    fn issued(name: &str) -> (String, Vec<u8>, EndorsementKey) {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        let ca_key = KeyPair::generate().unwrap();
        let ca_pem = params.self_signed(&ca_key).unwrap().pem();
        let issuer = Issuer::new(params, ca_key);

        let ek_key = KeyPair::generate().unwrap();
        let point = ek_key.public_key_raw();
        let ek = EndorsementKey::Ecc {
            x: point[1..33].try_into().unwrap(),
            y: point[33..].try_into().unwrap(),
        };
        let certificate = CertificateParams::default()
            .signed_by(&ek_key, &issuer)
            .unwrap();
        (ca_pem, certificate.der().to_vec(), ek)
    }

    #[test]
    fn ek_certificates_must_be_issued_by_the_ca_for_the_key() {
        let dir = tempfile::tempdir().unwrap();
        let (ca, certificate, ek) = issued("TPM manufacturer");
        let ca_file = dir.path().join("ca.pem");
        fs::write(&ca_file, &ca).unwrap();
        let issuer = certified(&certificate, &ek, &ca_file).unwrap();
        assert!(issuer.contains("TPM manufacturer"), "{issuer}");

        let (other_ca, _, other_ek) = issued("TPM manufacturer");
        let other_file = dir.path().join("other.pem");
        fs::write(&other_file, other_ca).unwrap();
        let error = certified(&certificate, &ek, &other_file).unwrap_err();
        assert!(error.to_string().contains("not signed"), "{error}");
        let error = certified(&certificate, &other_ek, &ca_file).unwrap_err();
        assert!(error.to_string().contains("another key"), "{error}");
    }
}

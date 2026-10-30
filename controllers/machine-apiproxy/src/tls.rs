//! Server-side mTLS configuration.

use std::sync::Arc;

use anyhow::Context;
use anyhow::ensure;
use machine_apiproxy::ApiConfig;
use rustls::RootCertStore;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::pem::PemObject;
use rustls::server::ServerConfig;
use rustls::server::WebPkiClientVerifier;

/// The TLS 1.3/1.2, h2-only server configuration of `config`'s identity, requiring client
/// certificates issued by its client CA.
///
/// # Errors
///
/// When a certificate or the key is unusable.
pub fn server_config(config: &ApiConfig) -> anyhow::Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut roots = RootCertStore::empty();
    for certificate in certificates(config.client_ca.pem()).context("the client CA")? {
        roots
            .add(certificate)
            .context("invalid client CA certificate")?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .context("building the client certificate verifier")?;

    let chain = certificates(config.certificate.pem()).context("the server certificate")?;
    let key = PrivateKeyDer::from_pem_slice(config.private_key.expose_pem().as_bytes())
        .context("reading the private key")?;

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::ALL_VERSIONS)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .context("invalid server certificate or key")?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

/// The certificates of `pem`, of which there must be one at least.
fn certificates(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certificates = CertificateDer::pem_slice_iter(pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .context("reading PEM certificates")?;
    ensure!(!certificates.is_empty(), "no certificate");
    Ok(certificates)
}

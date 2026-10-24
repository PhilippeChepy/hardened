//! Server-side mTLS configuration.

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, ensure};
use rustls::RootCertStore;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::{ServerConfig, WebPkiClientVerifier};

/// PEM CA bundle that client certificates must chain to.
pub const CLIENT_CA: &str = "client-ca.pem";
/// PEM server certificate chain, leaf first.
pub const CERTIFICATE: &str = "cert.pem";
/// PEM server private key.
pub const PRIVATE_KEY: &str = "key.pem";

/// Builds the TLS 1.3/1.2, h2-only server configuration from the PEM files in `dir`, requiring
/// client certificates issued by [`CLIENT_CA`].
pub fn server_config(dir: &Path) -> anyhow::Result<ServerConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut roots = RootCertStore::empty();
    for cert in read_certificates(&dir.join(CLIENT_CA))? {
        roots.add(cert).context("invalid client CA certificate")?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .context("building client certificate verifier")?;

    let chain = read_certificates(&dir.join(CERTIFICATE))?;
    let key_path = dir.join(PRIVATE_KEY);
    let key = PrivateKeyDer::from_pem_file(&key_path).with_context(|| format!("reading {}", key_path.display()))?;

    let mut config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(rustls::ALL_VERSIONS)?
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .context("invalid server certificate or key")?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(config)
}

fn read_certificates(path: &Path) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(Iterator::collect::<Result<Vec<_>, _>>)
        .with_context(|| format!("reading {}", path.display()))?;
    ensure!(!certs.is_empty(), "{} contains no certificate", path.display());
    Ok(certs)
}

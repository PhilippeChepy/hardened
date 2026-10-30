//! Certificates for tests.

/// A self-signed certificate and its key, PEM.
#[must_use]
pub fn certificate_and_key() -> (String, String) {
    let key = rcgen::KeyPair::generate().expect("a key pair");
    let certificate = rcgen::CertificateParams::new(vec!["x".into()])
        .expect("valid parameters")
        .self_signed(&key)
        .expect("a self-signed certificate");
    (certificate.pem(), key.serialize_pem())
}

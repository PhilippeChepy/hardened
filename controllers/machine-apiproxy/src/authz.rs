//! Client identity and per-call authorization.

use anyhow::Context;
use machine_apiproxy::Role;
use rustls::ServerConnection;
use tonic::Status;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;
use x509_parser::prelude::X509Error;

/// The client of a connection, as named by the certificate the TLS verifier accepted.
#[derive(Debug, PartialEq, Eq)]
pub struct Client {
    /// The certificate's Common Name (CN), if it has one.
    pub common_name: Option<String>,
    /// The role its Organization grants: without one, every call is refused.
    pub role: Option<Role>,
}

impl Client {
    /// Reads the client from the leaf certificate of an established mTLS session.
    pub fn from_session(session: &ServerConnection) -> anyhow::Result<Self> {
        let leaf = session
            .peer_certificates()
            .and_then(<[_]>::first)
            .context("no client certificate")?;
        Self::from_certificate(leaf)
    }

    /// Parses a DER leaf certificate, which the TLS verifier must already have accepted.
    fn from_certificate(der: &[u8]) -> anyhow::Result<Self> {
        let (_, certificate) = X509Certificate::from_der(der)
            .map_err(X509Error::from)
            .context("unparsable client certificate")?;
        let subject = certificate.subject();
        let common_name = subject
            .iter_common_name()
            .find_map(|cn| cn.as_str().ok())
            .map(str::to_owned);
        let organizations = subject
            .iter_organization()
            .filter_map(|organization| organization.as_str().ok());
        Ok(Self {
            common_name,
            role: Role::from_organizations(organizations),
        })
    }

    /// Decides whether this client may call the gRPC method at `path`: the status refusing the
    /// call if not.
    pub fn authorize(&self, path: &str) -> Result<(), Status> {
        let Some(role) = self.role else {
            return Err(Status::unauthenticated(
                "client certificate carries no hardened role",
            ));
        };
        let required = Role::required_for(path);
        if role >= required {
            Ok(())
        } else {
            Err(Status::permission_denied(format!(
                "method requires the {required} role"
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use rcgen::CertificateParams;
    use rcgen::DistinguishedName;
    use rcgen::DnType;
    use rcgen::KeyPair;
    use tonic::Code;

    use super::*;

    #[test]
    fn readers_only_reach_read_only_methods() {
        let reader = Client {
            common_name: None,
            role: Some(Role::Reader),
        };
        assert!(
            reader
                .authorize("/hardened.machine.v1.Machine/Version")
                .is_ok()
        );
        assert!(
            reader
                .authorize("/hardened.workloads.v1.Workloads/Logs")
                .is_ok()
        );
        for path in [
            "/hardened.machine.v1.Machine/Reboot",
            "/hardened.workloads.v1.Workloads/Apply",
            "/hardened.future.v1.Future/Thing",
            // Encoded or decorated variants of read-only paths are unknown, hence admin-only.
            "/hardened.machine.v1.Machine/%56ersion",
            "/hardened.machine.v1.Machine/Version/",
            "",
        ] {
            let status = reader.authorize(path).unwrap_err();
            assert_eq!(status.code(), Code::PermissionDenied, "{path}");
            assert_eq!(status.message(), "method requires the admin role");
        }
        let nobody = Client {
            common_name: None,
            role: None,
        };
        let status = nobody
            .authorize("/hardened.machine.v1.Machine/Version")
            .unwrap_err();
        assert_eq!(status.code(), Code::Unauthenticated);
    }

    fn client(organization: Option<&str>) -> Client {
        let mut params = CertificateParams::default();
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "alice");
        if let Some(organization) = organization {
            params
                .distinguished_name
                .push(DnType::OrganizationName, organization);
        }
        let key = KeyPair::generate().unwrap();
        let certificate = params.self_signed(&key).unwrap();
        Client::from_certificate(certificate.der()).unwrap()
    }

    #[test]
    fn role_comes_from_the_organization() {
        assert_eq!(
            client(Some(Role::Admin.organization())),
            Client {
                common_name: Some("alice".into()),
                role: Some(Role::Admin)
            }
        );
        assert_eq!(
            client(Some("hardened:root")),
            Client {
                common_name: Some("alice".into()),
                role: None
            }
        );
        assert_eq!(client(None).role, None);
    }
}

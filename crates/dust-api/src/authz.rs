//! Client identity and per-call authorization.

use dust_proto::{NoRole, Role};
use rustls::ServerConnection;
use x509_parser::prelude::{FromDer, X509Certificate, X509Error};

/// The client of a connection, as named by the certificate the TLS verifier accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Client {
    Authenticated(Identity),
    /// The certificate chains to the client CA but grants no role, so every call is refused.
    Unauthenticated {
        common_name: Option<String>,
        reason: NoRole,
    },
}

/// A client holding a role: only these can be authorized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    common_name: Option<String>,
    role: Role,
}

/// Why no [`Client`] can be read from a TLS session.
#[derive(Debug, thiserror::Error)]
pub enum CertificateError {
    #[error("no client certificate")]
    Missing,
    #[error("unparsable client certificate")]
    Unparsable(#[source] X509Error),
}

impl Client {
    /// Reads the client from the leaf certificate of an established mTLS session.
    pub fn from_session(session: &ServerConnection) -> Result<Self, CertificateError> {
        let leaf = session
            .peer_certificates()
            .and_then(<[_]>::first)
            .ok_or(CertificateError::Missing)?;
        Self::from_certificate(leaf)
    }

    /// Parses a DER leaf certificate, which the TLS verifier must already have accepted.
    fn from_certificate(der: &[u8]) -> Result<Self, CertificateError> {
        let (_, cert) = X509Certificate::from_der(der).map_err(|e| CertificateError::Unparsable(e.into()))?;
        let subject = cert.subject();
        let common_name = subject
            .iter_common_name()
            .find_map(|cn| cn.as_str().ok())
            .map(str::to_owned);
        Ok(
            match Role::from_organizations(subject.iter_organization().filter_map(|org| org.as_str().ok())) {
                Ok(role) => Self::Authenticated(Identity { common_name, role }),
                Err(reason) => Self::Unauthenticated { common_name, reason },
            },
        )
    }

    pub fn common_name(&self) -> Option<&str> {
        match self {
            Self::Authenticated(identity) => identity.common_name.as_deref(),
            Self::Unauthenticated { common_name, .. } => common_name.as_deref(),
        }
    }
}

/// Proof that a call passed [`Identity::authorize`], required to forward it.
#[derive(Debug)]
#[must_use]
pub struct Authorized(());

/// The client's role is below the one the method requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PermissionDenied {
    pub required: Role,
}

impl Identity {
    pub fn role(&self) -> Role {
        self.role
    }

    /// Decides whether this client may call the gRPC method at `path`.
    pub fn authorize(&self, path: &str) -> Result<Authorized, PermissionDenied> {
        let required = Role::required_for(path);
        if self.role >= required {
            Ok(Authorized(()))
        } else {
            Err(PermissionDenied { required })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(role: Role) -> Identity {
        Identity {
            common_name: None,
            role,
        }
    }

    #[test]
    fn readers_only_reach_read_only_methods() {
        let reader = identity(Role::Reader);
        assert!(reader.authorize("/hardened.v1.Machine/Version").is_ok());
        assert!(reader.authorize("/hardened.v1.Workloads/Logs").is_ok());
        for path in [
            "/hardened.v1.Machine/Reboot",
            "/hardened.v1.Workloads/Apply",
            "/hardened.v1.Future/Thing",
            // Encoded or decorated variants of read-only paths are unknown, hence admin-only.
            "/hardened.v1.Machine/%56ersion",
            "/hardened.v1.Machine/Version/",
            "",
        ] {
            assert_eq!(
                reader.authorize(path).unwrap_err(),
                PermissionDenied { required: Role::Admin },
                "{path}"
            );
        }
    }

    #[test]
    fn admins_reach_everything() {
        let admin = identity(Role::Admin);
        for path in ["/hardened.v1.Machine/Version", "/hardened.v1.Machine/Reboot", "/x/y"] {
            assert!(admin.authorize(path).is_ok(), "{path}");
        }
    }

    fn client(org: Option<&str>) -> Client {
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, "alice");
        if let Some(org) = org {
            params.distinguished_name.push(rcgen::DnType::OrganizationName, org);
        }
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        Client::from_certificate(cert.der()).unwrap()
    }

    #[test]
    fn role_comes_from_the_organization() {
        assert_eq!(
            client(Some(Role::ADMIN_ORG)),
            Client::Authenticated(Identity {
                common_name: Some("alice".into()),
                role: Role::Admin
            })
        );
        assert_eq!(
            client(Some("hardened:root")),
            Client::Unauthenticated {
                common_name: Some("alice".into()),
                reason: NoRole::Missing
            }
        );
        assert_eq!(client(None).common_name(), Some("alice"));
    }

    #[test]
    fn garbage_is_unparsable() {
        assert!(matches!(
            Client::from_certificate(b"not DER"),
            Err(CertificateError::Unparsable(_))
        ));
    }
}

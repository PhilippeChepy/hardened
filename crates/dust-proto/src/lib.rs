//! The dust API.
//!
//! dust-init serves it on a local unix socket ([`CONTROL_SOCKET`]); `dust-api`, a sandboxed child
//! of dust-init, exposes it remotely over mTLS, enforcing [`Role`]s derived from the client certificate.

include!(concat!(env!("OUT_DIR"), "/hardened.rs"));

pub use hardened::v1;

/// Path of dust-init's control socket, bind-mounted into the sandbox of `dust-api`.
pub const CONTROL_SOCKET: &str = "/run/dust/control.sock";

/// Authorization level of an API client, carried in the client certificate's Organization (O).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Read-only access: inventory, logs, attestation evidence.
    Reader,
    /// Full access, including workload changes and power management.
    Admin,
}

impl Role {
    /// Certificate Organization value for the reader role.
    pub const READER_ORG: &str = "hardened:reader";
    /// Certificate Organization value for the admin role.
    pub const ADMIN_ORG: &str = "hardened:admin";

    /// Parses a certificate Organization value.
    pub fn from_organization(org: &str) -> Option<Self> {
        match org {
            Self::READER_ORG => Some(Self::Reader),
            Self::ADMIN_ORG => Some(Self::Admin),
            _ => None,
        }
    }

    /// The certificate Organization value carrying this role.
    pub fn organization(self) -> &'static str {
        match self {
            Self::Reader => Self::READER_ORG,
            Self::Admin => Self::ADMIN_ORG,
        }
    }

    /// The single role named by a certificate subject's Organization values. Values naming no
    /// role are ignored; repeating a role is fine, naming two different ones is not.
    pub fn from_organizations<'a>(organizations: impl IntoIterator<Item = &'a str>) -> Result<Self, NoRole> {
        let mut roles = organizations.into_iter().filter_map(Self::from_organization);
        let role = roles.next().ok_or(NoRole::Missing)?;
        if roles.all(|other| other == role) {
            Ok(role)
        } else {
            Err(NoRole::Conflicting)
        }
    }

    /// Minimum role required to call the gRPC method at `path` (`/package.Service/Method`).
    ///
    /// Unknown methods require [`Role::Admin`], so new RPCs are safe by default.
    pub fn required_for(path: &str) -> Self {
        const READ_ONLY: &[&str] = &[
            "/hardened.v1.Machine/Version",
            "/hardened.v1.Machine/Logs",
            "/hardened.v1.Machine/GetSettings",
            "/hardened.v1.Workloads/List",
            "/hardened.v1.Workloads/Logs",
            "/hardened.v1.Attestation/Pcrs",
            "/hardened.v1.Attestation/EventLog",
            "/hardened.v1.Attestation/Quote",
        ];
        if READ_ONLY.contains(&path) {
            Self::Reader
        } else {
            Self::Admin
        }
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Reader => "reader",
            Self::Admin => "admin",
        })
    }
}

/// Why a certificate grants no role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoRole {
    /// No Organization value names a role.
    Missing,
    /// Organization values name different roles.
    Conflicting,
}

#[cfg(test)]
mod tests {
    use super::{NoRole, Role};

    #[test]
    fn unknown_methods_require_admin() {
        assert_eq!(Role::required_for("/hardened.v1.Machine/Version"), Role::Reader);
        assert_eq!(Role::required_for("/hardened.v1.Machine/Reboot"), Role::Admin);
        assert_eq!(Role::required_for("/hardened.v1.Future/Thing"), Role::Admin);
        assert!(Role::Admin > Role::Reader);
    }

    #[test]
    fn single_role_per_certificate() {
        assert_eq!(Role::from_organizations([Role::READER_ORG]), Ok(Role::Reader));
        assert_eq!(
            Role::from_organizations(["acme", Role::ADMIN_ORG, Role::ADMIN_ORG]),
            Ok(Role::Admin)
        );
        assert_eq!(Role::from_organizations([]), Err(NoRole::Missing));
        assert_eq!(Role::from_organizations(["hardened:root"]), Err(NoRole::Missing));
        assert_eq!(
            Role::from_organizations([Role::READER_ORG, Role::ADMIN_ORG]),
            Err(NoRole::Conflicting)
        );
    }
}

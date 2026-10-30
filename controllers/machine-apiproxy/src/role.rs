//! Authorization levels of API clients.

use std::fmt;

/// Authorization level of an API client, carried in the client certificate's Organization (O).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Role {
    /// Read-only access: inventory, logs, attestation evidence.
    Reader,
    /// Full access, including workload changes and power management.
    Admin,
}

impl Role {
    /// Parses a certificate Organization value.
    #[must_use]
    pub fn from_organization(organization: &str) -> Option<Self> {
        [Self::Reader, Self::Admin]
            .into_iter()
            .find(|role| role.organization() == organization)
    }

    /// The certificate Organization value carrying this role.
    #[must_use]
    pub fn organization(self) -> &'static str {
        match self {
            Self::Reader => "hardened:reader",
            Self::Admin => "hardened:admin",
        }
    }

    /// The single role named by a certificate subject's Organization values. Values naming no
    /// role are ignored; repeating a role is fine, naming two different ones grants none.
    #[must_use]
    pub fn from_organizations<'org>(
        organizations: impl IntoIterator<Item = &'org str>,
    ) -> Option<Self> {
        let mut roles = organizations
            .into_iter()
            .filter_map(Self::from_organization);
        let role = roles.next()?;
        roles.all(|other| other == role).then_some(role)
    }

    /// Minimum role required to call the gRPC method at `path` (`/package.Service/Method`).
    ///
    /// Unknown methods require [`Role::Admin`], so new RPCs are safe by default.
    #[must_use]
    pub fn required_for(path: &str) -> Self {
        const READ_ONLY: &[&str] = &[
            "/hardened.machine.v1.Machine/Version",
            "/hardened.machine.v1.Machine/Logs",
            "/hardened.machine.v1.Machine/GetSettings",
            "/hardened.machine.v1.Machine/Storage",
            "/hardened.machine.v1.Machine/Time",
            "/hardened.services.v1.Services/List",
            "/hardened.services.v1.Services/Get",
            "/hardened.services.v1.Services/Logs",
            "/hardened.workloads.v1.Workloads/List",
            "/hardened.workloads.v1.Workloads/Logs",
            "/hardened.attestation.v1.Attestation/Pcrs",
            "/hardened.attestation.v1.Attestation/EventLog",
            "/hardened.attestation.v1.Attestation/Quote",
        ];
        if READ_ONLY.contains(&path) {
            Self::Reader
        } else {
            Self::Admin
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Reader => "reader",
            Self::Admin => "admin",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_methods_require_admin() {
        assert_eq!(
            Role::required_for("/hardened.machine.v1.Machine/Version"),
            Role::Reader
        );
        assert_eq!(
            Role::required_for("/hardened.machine.v1.Machine/Storage"),
            Role::Reader
        );
        assert_eq!(
            Role::required_for("/hardened.machine.v1.Machine/Time"),
            Role::Reader
        );
        assert_eq!(
            Role::required_for("/hardened.machine.v1.Machine/Reboot"),
            Role::Admin
        );
        assert_eq!(
            Role::required_for("/hardened.future.v1.Future/Thing"),
            Role::Admin
        );
        for method in [
            "/hardened.attestation.v1.Attestation/Pcrs",
            "/hardened.attestation.v1.Attestation/EventLog",
            "/hardened.attestation.v1.Attestation/Quote",
            "/hardened.workloads.v1.Workloads/Logs",
            "/hardened.services.v1.Services/Get",
        ] {
            assert_eq!(Role::required_for(method), Role::Reader, "{method}");
        }
        for method in [
            "/hardened.services.v1.Services/Stop",
            "/hardened.services.v1.Services/Reload",
            "/hardened.workloads.v1.Workloads/Exec",
        ] {
            assert_eq!(Role::required_for(method), Role::Admin, "{method}");
        }
        assert!(Role::Admin > Role::Reader, "admins may do what readers may");
    }

    #[test]
    fn single_role_per_certificate() {
        assert_eq!(
            Role::from_organizations([Role::Reader.organization()]),
            Some(Role::Reader)
        );
        assert_eq!(
            Role::from_organizations([
                "acme",
                Role::Admin.organization(),
                Role::Admin.organization()
            ]),
            Some(Role::Admin)
        );
        assert_eq!(Role::from_organizations([]), None);
        assert_eq!(Role::from_organizations(["hardened:root"]), None);
        assert_eq!(
            Role::from_organizations([Role::Reader.organization(), Role::Admin.organization()]),
            None
        );
    }
}

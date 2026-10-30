//! `[settings.dns]`.

use std::net::IpAddr;

use controllers_helpers::DomainName;
use serde::{Deserialize, Serialize};

/// `[settings.dns]`: the resolver configuration. Each list, when set, replaces what DHCP
/// provides.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsSettings {
    /// The name servers, in order of preference.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub name_servers: Vec<IpAddr>,
    /// The domains short names are searched in.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_list: Vec<DomainName>,
}

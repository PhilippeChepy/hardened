//! DNS domain names.

use crate::validated_string;

/// RFC 1123 domain name: dot-separated labels of 1-63 alphanumerics or '-', at most 253 chars.
pub(crate) fn check_domain_name(name: &str) -> Result<(), &'static str> {
    if name.is_empty() || name.len() > 253 {
        return Err("must be 1 to 253 characters");
    }
    let valid_label = |label: &str| {
        (1..=63).contains(&label.len())
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    if name.split('.').all(valid_label) {
        Ok(())
    } else {
        Err("labels must be 1-63 alphanumerics or '-', not starting or ending with '-'")
    }
}

validated_string!(
    /// DNS search domain, with the hostname syntax (so it cannot inject into `resolv.conf`).
    DomainName,
    "domain name",
    check_domain_name
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_names() {
        assert!("corp.example.com".parse::<DomainName>().is_ok());
        for bad in ["", "a b", "a..b", "-a.com", "a\nnameserver 1.2.3.4"] {
            assert!(bad.parse::<DomainName>().is_err(), "{bad:?}");
        }
    }
}

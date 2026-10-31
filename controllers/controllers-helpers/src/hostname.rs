//! Host names.

use crate::domain_name;
use crate::validated_string;

validated_string!(
    const
    /// RFC 1123 hostname.
    Hostname,
    "hostname",
    domain_name::check_domain_name
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hostnames() {
        assert!("a-b.example.com".parse::<Hostname>().is_ok());
        for bad in ["", "-a", "a-", "a..b", "a_b", &"a".repeat(64)] {
            assert!(bad.parse::<Hostname>().is_err(), "{bad:?}");
        }
    }
}

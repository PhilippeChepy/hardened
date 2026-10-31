//! DNS domain names.

use crate::validated_string;

/// RFC 1123 domain name: dot-separated labels of 1-63 alphanumerics or '-', at most 253 chars.
/// A `const fn`, for `from_static`.
pub(crate) const fn check_domain_name(name: &str) -> Result<(), &'static str> {
    if !matches!(name.len(), 1..=253) {
        return Err("must be 1 to 253 characters");
    }
    let mut rest = name.as_bytes();
    loop {
        let (label, after) = first_label(rest);
        if !valid_label(label) {
            return Err(
                "labels must be 1-63 alphanumerics or '-', not starting or ending with '-'",
            );
        }
        match after {
            Some(after) => rest = after,
            None => return Ok(()),
        }
    }
}

/// The label before the first dot of `name`, and what follows that dot, if any.
const fn first_label(name: &[u8]) -> (&[u8], Option<&[u8]>) {
    let mut i = 0;
    while i < name.len() {
        if name[i] == b'.' {
            let (label, dot_and_rest) = name.split_at(i);
            return (label, Some(dot_and_rest.split_at(1).1));
        }
        i += 1;
    }
    (name, None)
}

/// 1-63 alphanumerics or '-', not starting or ending with '-'.
const fn valid_label(label: &[u8]) -> bool {
    let (Some(&first), Some(&last)) = (label.first(), label.last()) else {
        return false;
    };
    label.len() <= 63 && first != b'-' && last != b'-' && alphanumerics_or_hyphens(label)
}

const fn alphanumerics_or_hyphens(bytes: &[u8]) -> bool {
    let mut i = 0;
    while i < bytes.len() {
        if !(bytes[i].is_ascii_alphanumeric() || bytes[i] == b'-') {
            return false;
        }
        i += 1;
    }
    true
}

validated_string!(
    const
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

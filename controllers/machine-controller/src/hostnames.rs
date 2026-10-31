//! The hostnames machine-controller chooses from what platforms and DHCP servers offer.

use controllers_helpers::Hostname;

const HARDENED: Hostname = Hostname::from_static("hardened");

/// Cleans up a hostname offered by a platform or DHCP server: first word, trailing dots
/// stripped, lowercased; falls back to its first label when the whole name is invalid.
#[must_use]
pub fn sanitize(raw: &str) -> Option<Hostname> {
    let name = raw
        .split_whitespace()
        .next()?
        .trim_end_matches('.')
        .to_ascii_lowercase();
    let first_label = name.split('.').next().unwrap_or_default().to_owned();
    name.parse().ok().or_else(|| first_label.parse().ok())
}

/// `hardened-<up to 8 lowercase alphanumerics of the instance ID>`, or `hardened`.
#[must_use]
pub fn from_instance_id(instance_id: Option<&str>) -> Hostname {
    let short: String = instance_id
        .unwrap_or_default()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .take(8)
        .map(|c| c.to_ascii_lowercase())
        .collect();
    let name = if short.is_empty() {
        "hardened".to_owned()
    } else {
        format!("hardened-{short}")
    };
    // A prefix and at most 8 alphanumerics: always a valid label, `hardened` otherwise.
    name.parse().unwrap_or(HARDENED)
}

/// The first label.
#[must_use]
pub fn short(hostname: &Hostname) -> &str {
    let name = hostname.as_str();
    name.split('.').next().unwrap_or(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitizes_offered_names() {
        assert_eq!(
            sanitize("Web-1.Example.COM.").unwrap().as_str(),
            "web-1.example.com"
        );
        assert_eq!(
            short(&sanitize("ip-10-0-0-1.ec2.internal other.name").unwrap()),
            "ip-10-0-0-1"
        );
        assert_eq!(
            sanitize("host.under_score.example").unwrap().as_str(),
            "host",
            "the first label of an invalid name"
        );
        assert_eq!(sanitize("   "), None);
        assert_eq!(sanitize("-bad.example.com_"), None);
    }

    #[test]
    fn names_from_instance_ids() {
        assert_eq!(
            from_instance_id(Some("i-0ABCdef1234567890")).as_str(),
            "hardened-i0abcdef"
        );
        assert_eq!(from_instance_id(Some("--..--")).as_str(), "hardened");
        assert_eq!(from_instance_id(Some("")).as_str(), "hardened");
        assert_eq!(from_instance_id(None).as_str(), "hardened");
    }
}

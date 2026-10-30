//! Sysctl keys.

use controllers_helpers::validated_string;

validated_string!(
    /// Sysctl key, e.g. `net.ipv4.ip_forward`: dot-separated non-empty components that cannot
    /// escape `/proc/sys`.
    SysctlKey,
    "sysctl key",
    check_sysctl_key
);

fn check_sysctl_key(key: &str) -> Result<(), &'static str> {
    let valid = |part: &str| {
        !part.is_empty()
            && part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '*'))
    };
    if key.split('.').all(valid) {
        Ok(())
    } else {
        Err("must be dot-separated alphanumeric components")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysctl_keys_stay_in_proc_sys() {
        assert!("net.ipv4.ip_forward".parse::<SysctlKey>().is_ok());
        for bad in ["", "net..x", "net./x", "../x", "a.b c"] {
            assert!(bad.parse::<SysctlKey>().is_err(), "{bad:?}");
        }
    }
}

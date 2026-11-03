//! Network interface names.

use controllers_helpers::validated_string;

validated_string!(
    /// A network interface's kernel name (e.g. `eth0`): 1 to 15 bytes (`IFNAMSIZ` with its NUL),
    /// no `/`, `:`, whitespace or control characters, not `.` or `..`, as the kernel requires.
    InterfaceName,
    "interface name",
    check_interface_name
);

fn check_interface_name(name: &str) -> Result<(), &'static str> {
    if !matches!(name.len(), 1..=15) {
        return Err("must be 1 to 15 bytes");
    }
    if name == "." || name == ".." {
        return Err("must not be . or ..");
    }
    if name
        .chars()
        .any(|c| c == '/' || c == ':' || c.is_whitespace() || c.is_control())
    {
        return Err("must not contain '/', ':', whitespace or control characters");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_kernel_names() {
        for name in ["eth0", "enp0s31f6", "ens4", "a", "x".repeat(15).as_str()] {
            assert!(name.parse::<InterfaceName>().is_ok(), "{name:?}");
        }
        for name in [
            "",
            ".",
            "..",
            "eth/0",
            "eth0:1",
            "eth 0",
            "eth\n",
            &"x".repeat(16),
        ] {
            assert!(name.parse::<InterfaceName>().is_err(), "{name:?}");
        }
    }
}

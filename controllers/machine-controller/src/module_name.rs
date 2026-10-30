//! Kernel module names.

use controllers_helpers::validated_string;

validated_string!(
    /// Kernel module name: alphanumerics, '_' or '-' (`modules.dep` treats both as equivalent).
    ModuleName,
    "kernel module name",
    check_module_name
);

fn check_module_name(name: &str) -> Result<(), &'static str> {
    if (1..=64).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        Ok(())
    } else {
        Err("must be 1-64 alphanumerics, '_' or '-'")
    }
}

impl ModuleName {
    /// The name `modules.dep` uses: dashes replaced by underscores.
    #[must_use]
    pub fn to_canonical(&self) -> String {
        self.0.replace('-', "_")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_names() {
        assert_eq!(
            "mlx5-core".parse::<ModuleName>().unwrap().to_canonical(),
            "mlx5_core"
        );
        for bad in ["", "../evil", &"a".repeat(65)] {
            assert!(bad.parse::<ModuleName>().is_err(), "{bad:?}");
        }
    }
}

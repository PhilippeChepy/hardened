//! Host paths below `/var`.

use controllers_helpers::validated_string;

use crate::container_path;

validated_string!(
    /// Absolute, normalized host path below `/var`, the only persistent writable location;
    /// without commas, like a [`crate::ContainerPath`].
    VarPath,
    "host path",
    check_var_path
);

fn check_var_path(path: &str) -> Result<(), &'static str> {
    container_path::check_absolute(path)?;
    if path
        .strip_prefix("/var/")
        .is_some_and(|rest| !rest.is_empty())
    {
        Ok(())
    } else {
        Err("must be below /var")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn var_paths() {
        assert!("/var/lib/web".parse::<VarPath>().is_ok());
        for bad in [
            "/var",
            "/var/",
            "/etc",
            "/var/../etc",
            "var/lib",
            "/var//x",
            "/var/./x",
            "/var/a,b",
        ] {
            assert!(bad.parse::<VarPath>().is_err(), "{bad:?}");
        }
    }
}

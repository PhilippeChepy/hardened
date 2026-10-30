//! Paths inside containers.

use controllers_helpers::validated_string;

validated_string!(
    /// Absolute, normalized path inside a container, without commas: `ctr run --mount` separates
    /// its options with them.
    ContainerPath,
    "container path",
    check_absolute
);

/// An absolute path, without `.`, `..` or empty segments, nor commas.
pub(crate) fn check_absolute(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("must be absolute");
    }
    // Raw segments: `Path::components` would silently normalize `.` and `//` away.
    let denormalized = path != "/"
        && path
            .split('/')
            .skip(1)
            .any(|segment| matches!(segment, "" | "." | ".."));
    if denormalized || path.contains('\0') {
        return Err("must be normalized (no '.', '..' or '//')");
    }
    if path.contains(',') {
        return Err("must not contain ','");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_paths() {
        assert!("/data".parse::<ContainerPath>().is_ok());
        assert!("/".parse::<ContainerPath>().is_ok());
        for bad in ["data", "/a/../b", "/a//b", "/a/./b", "/data,rw"] {
            assert!(bad.parse::<ContainerPath>().is_err(), "{bad:?}");
        }
    }
}

//! Workload names.

use crate::validated_string;

validated_string!(
    /// Workload name, doubling as containerd ID, snapshot key, cgroup and log file name:
    /// 1-63 lowercase alphanumerics or '-', not starting with '-'.
    WorkloadName,
    "workload name",
    check_workload_name
);

fn check_workload_name(name: &str) -> Result<(), &'static str> {
    if (1..=63).contains(&name.len())
        && name
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        && !name.starts_with('-')
    {
        Ok(())
    } else {
        Err("must be 1-63 lowercase alphanumerics or '-', not starting with '-'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_names() {
        assert!("web-1".parse::<WorkloadName>().is_ok());
        for bad in ["", "Web", "-web", "a/b", &"a".repeat(64)] {
            assert!(bad.parse::<WorkloadName>().is_err(), "{bad:?}");
        }
    }
}

//! Workload names.

use crate::validated_string;

validated_string!(
    /// Workload name, doubling as containerd ID, snapshot key, cgroup and log file name:
    /// 1-63 lowercase alphanumerics, separated by single '-' (containerd refuses `a--b`, `a-`).
    WorkloadName,
    "workload name",
    check_workload_name
);

fn check_workload_name(name: &str) -> Result<(), &'static str> {
    let words = name.split('-').all(|word| {
        !word.is_empty()
            && word
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
    });
    if name.len() <= 63 && words {
        Ok(())
    } else {
        Err("must be 1-63 lowercase alphanumerics, separated by single '-'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workload_names() {
        for good in ["web-1", "a", "a-b-c", &"a".repeat(63)] {
            assert!(good.parse::<WorkloadName>().is_ok(), "{good:?}");
        }
        for bad in [
            "",
            "Web",
            "-web",
            "web-",
            "a--b",
            "a/b",
            "a_b",
            &"a".repeat(64),
        ] {
            assert!(bad.parse::<WorkloadName>().is_err(), "{bad:?}");
        }
    }
}

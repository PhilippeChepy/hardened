//! containerd's container IDs.

use controllers_helpers::validated_string;

validated_string!(
    /// A container's ID, as containerd accepts it: up to 76 alphanumerics, separated by single
    /// '.', '_' or '-'; so never taken for an option of `ctr`.
    ContainerId,
    "container ID",
    check_container_id
);

fn check_container_id(id: &str) -> Result<(), &'static str> {
    let separated = id
        .split(['.', '_', '-'])
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_alphanumeric()));
    if id.len() <= 76 && separated {
        Ok(())
    } else {
        Err("must be up to 76 alphanumerics, separated by single '.', '_' or '-'")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_containerd_identifiers_only() {
        for good in ["workload-web", "a", "a.b_c-1", &"a".repeat(76)] {
            assert!(good.parse::<ContainerId>().is_ok(), "{good}");
        }
        for bad in ["", "-a", "a-", "a--b", "a b", "a/b", &"a".repeat(77)] {
            assert!(bad.parse::<ContainerId>().is_err(), "{bad}");
        }
    }
}

//! Node label keys and values (taint keys are qualified names too).

use controllers_helpers::validated_string;

validated_string!(
    /// A Kubernetes qualified name (label and taint keys): `[<DNS subdomain>/]<name>`.
    QualifiedName,
    "label or taint key",
    check_qualified_name
);

fn check_qualified_name(key: &str) -> Result<(), &'static str> {
    let (prefix, name) = match key.split_once('/') {
        Some((prefix, name)) => (Some(prefix), name),
        None => (None, key),
    };
    if prefix.is_some_and(|prefix| !is_dns_subdomain(prefix)) {
        Err("its prefix must be a lowercase DNS subdomain")
    } else if name.is_empty() || !is_label_value(name) {
        Err(
            "its name must be 1-63 alphanumerics, '-', '_' or '.', starting and ending with an \
             alphanumeric",
        )
    } else {
        Ok(())
    }
}

validated_string!(
    /// A label key kubelet may register the node with: a [`QualifiedName`], outside the
    /// `kubernetes.io` and `k8s.io` namespaces but for those of `kubelet.kubernetes.io` and
    /// `node.kubernetes.io`, and a few well-known labels. kubelet refuses to start with another.
    NodeLabelKey,
    "node label key",
    check_node_label_key
);

fn check_node_label_key(key: &str) -> Result<(), &'static str> {
    check_qualified_name(key)?;
    if is_settable_by_kubelet(key) {
        Ok(())
    } else {
        Err(
            "kubelet may only set the kubernetes.io and k8s.io labels of the \
             kubelet.kubernetes.io and node.kubernetes.io namespaces, and a few well-known ones",
        )
    }
}

/// Whether kubelet may set the label `key`, a qualified name (`IsKubeletLabel` in
/// `k8s.io/kubelet`).
#[must_use]
fn is_settable_by_kubelet(key: &str) -> bool {
    const LABELS: &[&str] = &[
        "kubernetes.io/hostname",
        "kubernetes.io/os",
        "kubernetes.io/arch",
        "topology.kubernetes.io/zone",
        "topology.kubernetes.io/region",
        "failure-domain.beta.kubernetes.io/zone",
        "failure-domain.beta.kubernetes.io/region",
        "beta.kubernetes.io/instance-type",
        "node.kubernetes.io/instance-type",
        "beta.kubernetes.io/os",
        "beta.kubernetes.io/arch",
    ];
    let in_namespace = |namespace: &str, suffix: &str| {
        namespace == suffix
            || namespace
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
    };
    let Some((namespace, _)) = key.split_once('/') else {
        return true;
    };
    let restricted = in_namespace(namespace, "kubernetes.io") || in_namespace(namespace, "k8s.io");
    !restricted
        || LABELS.contains(&key)
        || in_namespace(namespace, "kubelet.kubernetes.io")
        || in_namespace(namespace, "node.kubernetes.io")
}

validated_string!(
    /// A label value: empty, or 1-63 alphanumerics, '-', '_' or '.', starting and ending with an
    /// alphanumeric.
    LabelValue,
    "label value",
    check_label_value
);

fn check_label_value(value: &str) -> Result<(), &'static str> {
    if value.is_empty() || is_label_value(value) {
        Ok(())
    } else {
        Err(
            "must be at most 63 alphanumerics, '-', '_' or '.', starting and ending with an \
             alphanumeric",
        )
    }
}

#[must_use]
fn is_label_value(value: &str) -> bool {
    let edges_alphanumeric = value.starts_with(|c: char| c.is_ascii_alphanumeric())
        && value.ends_with(|c: char| c.is_ascii_alphanumeric());
    value.len() <= 63
        && edges_alphanumeric
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

#[must_use]
fn is_dns_subdomain(name: &str) -> bool {
    let label = |label: &str| {
        !label.is_empty()
            && label
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !label.starts_with('-')
            && !label.ends_with('-')
    };
    name.len() <= 253 && name.split('.').all(label)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_keys_and_values() {
        for good in [
            "app",
            "example.com/role",
            "a.b-c/x_y.z",
            "node.kubernetes.io/pool",
        ] {
            assert!(good.parse::<QualifiedName>().is_ok(), "{good}");
        }
        for bad in [
            "",
            "/x",
            "Example.com/x",
            "a/b/c",
            "-x",
            "x-",
            &"a".repeat(64),
            "a b",
        ] {
            assert!(bad.parse::<QualifiedName>().is_err(), "{bad:?}");
        }
        for good in ["", "v1", "a.b_c-d"] {
            assert!(good.parse::<LabelValue>().is_ok(), "{good:?}");
        }
        for bad in ["-a", "a,b", "a=b", &"a".repeat(64)] {
            assert!(bad.parse::<LabelValue>().is_err(), "{bad:?}");
        }
    }

    #[test]
    fn kubelet_label_namespaces() {
        let may_set = |key: &str| key.parse::<NodeLabelKey>().is_ok();
        for allowed in [
            "role",
            "example.com/role",
            "node.kubernetes.io/pool",
            "pool.node.kubernetes.io/x",
            "kubelet.kubernetes.io/x",
            "topology.kubernetes.io/zone",
            "notkubernetes.io/x",
        ] {
            assert!(may_set(allowed), "{allowed}");
        }
        for denied in [
            "node-role.kubernetes.io/worker",
            "kubernetes.io/role",
            "x.k8s.io/y",
            "node-restriction.kubernetes.io/x",
        ] {
            assert!(!may_set(denied), "{denied}");
        }
    }
}

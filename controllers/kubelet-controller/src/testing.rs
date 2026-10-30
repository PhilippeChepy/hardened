//! Settings for the tests of kubelet-controller and its users.

use controllers_helpers::base64_text;
use controllers_helpers::testing;

/// `[settings.kubernetes]` with every key set, durations in their normalized form.
pub fn full_toml() -> String {
    let (certificate, _) = testing::certificate_and_key();
    let certificate = base64_text::encode(certificate);
    let manifest = base64_text::encode(
        "apiVersion: v1\nkind: Pod\nmetadata:\n  name: web\nspec:\n  containers: []\n",
    );
    format!(
        r#"
api-server = "https://k8s.example.com:6443"
cluster-certificate = "{certificate}"
bootstrap-token = "abcdef.0123456789abcdef"
cluster-domain = "cluster.example"
cluster-dns-ip = ["10.96.0.10", "fd00::10"]
max-pods = 110
cloud-provider = "external"
eviction-max-pod-grace-period = 30
image-gc-high-threshold-percent = 90
image-gc-low-threshold-percent = 70
image-minimum-gc-age = "5m"
image-maximum-gc-age = "168h"

[node-labels]
"example.com/role" = "web"
"node.kubernetes.io/pool" = ""

[node-taints]
"example.com/gpu" = ["true:NoSchedule", ":PreferNoSchedule"]
dedicated = ["web:NoExecute"]

[static-pods.web]
manifest = "{manifest}"

[static-pods.off]
enabled = false
manifest = "{manifest}"

[kube-reserved]
cpu = "100m"
memory = "1.5Gi"

[system-reserved]
ephemeral-storage = "1Gi"
pid = "1000"

[eviction-hard]
"memory.available" = "100Mi"
"nodefs.available" = "10%"

[eviction-soft]
"memory.available" = "200Mi"
"imagefs.available" = "99.5%"

[eviction-soft-grace-period]
"memory.available" = "1m30s"
"imagefs.available" = "500ms"
"#
    )
}

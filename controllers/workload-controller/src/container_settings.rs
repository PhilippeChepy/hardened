//! `[settings.hardened.containers.<name>]`.

use serde::{Deserialize, Serialize};

use crate::ImageWorkload;

/// `[settings.hardened.containers.<name>]`: a workload declared in user-data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct ContainerSettings {
    /// When false, the workload is declared (it owns its name) but does not run.
    #[serde(default = "yes")]
    pub enabled: bool,
    /// What it runs, its keys next to `enabled`.
    #[serde(flatten)]
    pub workload: ImageWorkload,
}

fn yes() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_rejects_unknown_keys() {
        let text = r#"
enabled = false
image = "nginx:1.29"
command = ["nginx", "-g", "daemon off;"]
env = { FOO = "bar" }
privileged = true
restart = "on-failure"
mounts = [{ source = "/var/lib/web", destination = "/data", read-only = true }]
console = true
"#;
        let container: ContainerSettings = toml::from_str(text).unwrap();
        assert!(!container.enabled);
        assert_eq!(container.workload.command.len(), 3);
        let shown = toml::to_string(&container).unwrap();
        assert_eq!(
            toml::from_str::<ContainerSettings>(&shown).unwrap(),
            container
        );
        let typo = "image = \"nginx\"\nenable = false\n";
        assert!(toml::from_str::<ContainerSettings>(typo).is_err());
    }
}

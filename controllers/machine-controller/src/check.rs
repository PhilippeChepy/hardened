//! `machine-controller check-user-data`: validates a user-data file and prints its effective
//! settings.

use std::fs;
use std::path::Path;

use anyhow::Context as _;
use machine_controller::UserData;
use toml::Table;

/// What secrets show in place of their value.
const REDACTED: &str = "<redacted>";

/// Prints the settings of the user-data at `path` as TOML, secrets redacted.
pub fn run(path: &Path) -> anyhow::Result<()> {
    let raw = fs::read(path).with_context(|| path.display().to_string())?;
    let user_data = UserData::parse(&raw)?;
    let mut settings = Table::try_from(&user_data.settings)?;
    redact(&mut settings);
    print!("{}", toml::to_string_pretty(&settings)?);
    Ok(())
}

/// Replaces the secrets of serialized settings, which hold them as user-data does: the API's
/// private key, kubelet's bootstrap token, the registries' passwords and tokens.
fn redact(settings: &mut Table) {
    if let Some(api) = table(settings, &["hardened", "api"]) {
        replace(api, "private-key");
    }
    if let Some(kubernetes) = table(settings, &["kubernetes"]) {
        replace(kubernetes, "bootstrap-token");
    }
    let registry = table(settings, &["container-registry"]);
    let credentials = registry.and_then(|registry| registry.get_mut("credentials"));
    let credentials = credentials.and_then(toml::Value::as_array_mut);
    for credential in credentials.into_iter().flatten() {
        if let Some(credential) = credential.as_table_mut() {
            for key in ["password", "auth", "identitytoken"] {
                replace(credential, key);
            }
        }
    }
}

/// The table at `path` below `root`, if there is one.
fn table<'a>(root: &'a mut Table, path: &[&str]) -> Option<&'a mut Table> {
    path.iter()
        .try_fold(root, |table, key| table.get_mut(*key)?.as_table_mut())
}

/// Replaces the value of `key`, if set, with [`REDACTED`].
fn replace(table: &mut Table, key: &str) {
    if let Some(value) = table.get_mut(key) {
        *value = REDACTED.into();
    }
}

#[cfg(test)]
mod tests {
    use controllers_helpers::base64_text;
    use controllers_helpers::testing;

    use super::*;
    use crate::fake_controllers;

    #[test]
    fn secrets_are_redacted() {
        let (certificate, _) = testing::certificate_and_key();
        let certificate = base64_text::encode(certificate);
        let document = format!(
            "{}\n[settings.kubernetes]\n\
             api-server = \"https://k8s.example.com:6443\"\n\
             cluster-certificate = \"{certificate}\"\n\
             bootstrap-token = \"abcdef.0123456789abcdef\"\n\
             [[settings.container-registry.credentials]]\n\
             registry = \"docker.io\"\nusername = \"me\"\npassword = \"hunter2\"\n\
             [[settings.container-registry.credentials]]\n\
             registry = \"ghcr.io\"\nidentitytoken = \"token-1\"\n\
             [[settings.container-registry.credentials]]\n\
             registry = \"quay.io\"\nauth = \"bWU6aHVudGVyMg==\"\n",
            fake_controllers::api_user_data(),
        );
        let user_data = UserData::parse(document.as_bytes()).unwrap();
        let mut settings = Table::try_from(&user_data.settings).unwrap();
        let private_key = settings["hardened"]["api"]["private-key"].clone();
        redact(&mut settings);
        let shown = toml::to_string(&settings).unwrap();
        for secret in [
            private_key.as_str().unwrap(),
            "0123456789abcdef",
            "hunter2",
            "token-1",
            "bWU6aHVudGVyMg==",
        ] {
            assert!(!shown.contains(secret), "{secret} shown in {shown}");
        }
        assert!(shown.contains("private-key = \"<redacted>\""), "{shown}");
        assert!(shown.contains("username = \"me\""), "the rest is shown");
    }
}

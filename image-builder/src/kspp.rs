//! The kernel's hardening check, as Talos runs it on its kernels: kernel-hardening-checker
//! (`image-tools`) checks the kernel's configuration and the image's command line against the
//! KSPP's recommendations (and a few of its author's and other projects'). Every failing
//! recommendation must be one of the target's `kspp-exceptions`, with its reason, and every
//! exception must still fail: a stale one would hide the recommendation once it fails again.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context as _, bail};
use serde::Deserialize;

use crate::podman::Image;

/// One recommendation, as `kernel-hardening-checker -m json` reports it.
#[derive(Deserialize)]
struct Check {
    option_name: String,
    #[serde(rename = "type")]
    kind: String,
    desired_val: String,
    check_result: String,
    check_result_bool: bool,
}

/// Checks the kernel configuration `config` and the command line `cmdline` (a file) with the
/// checker of `assembly`, failing on what `exceptions` do not account for.
pub fn check(
    assembly: &Image,
    config: &Path,
    cmdline: &Path,
    exceptions: &BTreeMap<String, String>,
) -> anyhow::Result<()> {
    let output = assembly
        .container()
        .mount_ro(config, "/kspp/config")
        .mount_ro(cmdline, "/kspp/cmdline")
        .output(
            "python3 -c 'import kernel_hardening_checker; kernel_hardening_checker.main()' \
               -c /kspp/config -l /kspp/cmdline -m json",
        )
        .context("running kernel-hardening-checker")?;
    let checks: Vec<Check> =
        serde_json::from_str(&output).context("parsing kernel-hardening-checker's report")?;
    let failures = unexpected(&checks, exceptions);
    if !failures.is_empty() {
        bail!(
            "the kernel does not follow these hardening recommendations, nor do the target's \
             kspp-exceptions account for them:\n{}",
            failures.join("\n")
        );
    }
    eprintln!(
        "==> kernel hardening: {} recommendations followed, {} exceptions",
        checks
            .iter()
            .filter(|check| check.check_result_bool)
            .count(),
        exceptions.len()
    );
    Ok(())
}

/// What is wrong in `checks`, given `exceptions`: the failures they do not name, and the
/// exceptions that do not fail.
#[must_use]
fn unexpected(checks: &[Check], exceptions: &BTreeMap<String, String>) -> Vec<String> {
    let mut problems: Vec<String> = checks
        .iter()
        .filter(|check| !check.check_result_bool && !exceptions.contains_key(&check.option_name))
        .map(|check| {
            format!(
                "  {} ({}): wants {}, {}",
                check.option_name, check.kind, check.desired_val, check.check_result
            )
        })
        .collect();
    for option in exceptions.keys() {
        let failing = checks
            .iter()
            .any(|check| check.option_name == *option && !check.check_result_bool);
        if !failing {
            problems.push(format!("  {option}: an exception, but it does not fail"));
        }
    }
    problems
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(option: &str, ok: bool) -> Check {
        Check {
            option_name: option.to_owned(),
            kind: "kconfig".to_owned(),
            desired_val: "y".to_owned(),
            check_result: if ok { "OK" } else { "FAIL: \"is not set\"" }.to_owned(),
            check_result_bool: ok,
        }
    }

    #[test]
    fn failures_need_an_exception_and_exceptions_a_failure() {
        let checks = [
            check("CONFIG_BUG", true),
            check("CONFIG_MODULES", false),
            check("CONFIG_DEBUG_WX", false),
        ];
        let exceptions = BTreeMap::from([
            ("CONFIG_MODULES".to_owned(), "signed modules".to_owned()),
            ("CONFIG_BUG".to_owned(), "stale".to_owned()),
        ]);
        assert_eq!(
            unexpected(&checks, &exceptions),
            [
                "  CONFIG_DEBUG_WX (kconfig): wants y, FAIL: \"is not set\"",
                "  CONFIG_BUG: an exception, but it does not fail",
            ]
        );
    }
}

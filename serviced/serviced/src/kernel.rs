//! Kernel settings made at boot, before any service starts: LoadPin's pin, and the hardened sysctls
//! (services may change some later, from user-data).

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use tracing::{info, warn};

/// A regular file of the root filesystem, never a module.
const PIN_FILE: &str = "/usr/lib/os-release";

/// The hardened sysctls, `key = value` per line, which its recipe ships (and the image build
/// checks against the KSPP's recommendations). Those it leaves out, and why, are the target's
/// `kspp-exceptions`.
const SYSCTLS: &str = "/usr/lib/serviced/sysctls.conf";

/// Pins LoadPin to the root filesystem before anything else can load a kernel file: otherwise a
/// privileged workload loading the first module from `/var` would pin that filesystem instead.
/// LoadPin pins when it checks the file, before the kernel reads it as a module, so a regular
/// file of the root does (the kernel then rejects it as unsigned).
pub fn pin() {
    let result = rustix::fs::open(PIN_FILE, OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty())
        .and_then(|file| rustix::system::finit_module(&file, c"", 0));
    match result {
        Err(Errno::KEYREJECTED | Errno::NOEXEC | Errno::INVAL) => {
            info!("kernel files pinned to the root filesystem")
        }
        Ok(()) => warn!("{PIN_FILE} loaded as a kernel module"),
        Err(e) => warn!(error = %e, "cannot pin kernel files to the root filesystem"),
    }
}

/// Sets the hardened sysctls; those the kernel lacks, and invalid lines, are warned about.
pub fn apply_sysctls() {
    let text = match std::fs::read_to_string(SYSCTLS) {
        Ok(text) => text,
        Err(e) => {
            warn!(path = SYSCTLS, error = %e, "cannot read the hardened sysctls");
            return;
        }
    };
    for entry in parse(&text) {
        match entry {
            Ok((key, value)) => {
                let path = format!("/proc/sys/{}", key.replace('.', "/"));
                if let Err(e) = std::fs::write(path, value) {
                    warn!(key, value, error = %e, "cannot set sysctl");
                }
            }
            Err(line) => warn!(line, "invalid line in {SYSCTLS}"),
        }
    }
}

/// The `key = value` lines of `text`, blank lines skipped; an invalid line as is.
fn parse(text: &str) -> impl Iterator<Item = Result<(&str, &str), &str>> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(|line| {
            let (key, value) = line.split_once('=').ok_or(line)?;
            let (key, value) = (key.trim(), value.trim());
            let valid = !key.is_empty()
                && key
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || "._-".contains(c))
                && !key.split('.').any(|part| part.is_empty() || part == "..");
            if valid && !value.is_empty() {
                Ok((key, value))
            } else {
                Err(line)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_image_s_sysctls_parse() {
        let text = include_str!("../../../specs/targets/standard/components/serviced/sysctls.conf");
        assert!(parse(text).all(|entry| entry.is_ok()));
        assert!(parse(text).count() > 30);
    }

    #[test]
    fn parses_key_value_lines() {
        let text = "kernel.kptr_restrict = 2\n\nnet.ipv4.conf.all.rp_filter=1\nnot a line\n\
                    ../x = 1\nvm.mmap_min_addr =\n";
        let entries: Vec<_> = parse(text).collect();
        assert_eq!(
            entries,
            [
                Ok(("kernel.kptr_restrict", "2")),
                Ok(("net.ipv4.conf.all.rp_filter", "1")),
                Err("not a line"),
                Err("../x = 1"),
                Err("vm.mmap_min_addr ="),
            ]
        );
    }
}

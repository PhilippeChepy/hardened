//! Signing keys, in `build/keys/`: the only part of `build/` that is not disposable.
//!
//! Development keys are generated on first use. Release builds provide their own (e.g. from an
//! HSM-backed CI secret). The same keys give byte-identical images: Secure Boot signs the UKI,
//! the module key signs kernel modules with deterministic RSA signatures (the kernel's
//! `sign-file` adds no signing time), and the randstruct seed lays the kernel's structures out.

use std::path::Path;

use crate::Paths;
use crate::podman::Image;

/// The kernel module signing key: private key and X.509 certificate in one PEM file, as
/// `CONFIG_MODULE_SIG_KEY` expects. Handed to the kernel build as a secret.
const MODULES: &str = "modules.pem";
/// The seed of `CONFIG_RANDSTRUCT`'s layouts, 32 bytes as hex: secret, as the layout is to
/// whoever attacks the kernel without its build. Handed to the kernel build as a secret.
const RANDSTRUCT: &str = "randstruct.seed";

/// Generates the missing keys, with the openssl and `sh` of `image`.
pub fn ensure(paths: &Paths, image: &Image) -> anyhow::Result<()> {
    let keys = paths.keys();
    std::fs::create_dir_all(&keys)?;
    if !keys.join("db.key").exists() {
        eprintln!(
            "==> generating a development Secure Boot key in {}",
            keys.display()
        );
        generate(
            image,
            &keys,
            "openssl req -new -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
               -subj '/CN=hardened development Secure Boot key/' \
               -keyout /keys/db.key -out /keys/db.crt 2>/dev/null\n\
             openssl x509 -in /keys/db.crt -outform DER -out /keys/db.cer",
        )?;
    }
    if !keys.join(MODULES).exists() {
        eprintln!(
            "==> generating a development module signing key in {}",
            keys.display()
        );
        // The extensions of the kernel's own certs/default_x509.genkey.
        generate(
            image,
            &keys,
            &format!(
                "umask 077\n\
                 openssl req -new -x509 -newkey rsa:4096 -sha512 -nodes -days 36500 \
                   -subj '/CN=hardened development module signing key/' \
                   -addext basicConstraints=critical,CA:FALSE -addext keyUsage=digitalSignature \
                   -addext subjectKeyIdentifier=hash -addext authorityKeyIdentifier=keyid \
                   -keyout /tmp/key.pem -out /tmp/cert.pem 2>/dev/null\n\
                 cat /tmp/key.pem /tmp/cert.pem > /keys/{MODULES}"
            ),
        )?;
    }
    if !keys.join(RANDSTRUCT).exists() {
        eprintln!(
            "==> generating a development randstruct seed in {}",
            keys.display()
        );
        generate(
            image,
            &keys,
            &format!(
                "umask 077
openssl rand -hex 32 > /keys/{RANDSTRUCT}"
            ),
        )?;
    }
    Ok(())
}

fn generate(image: &Image, keys: &Path, script: &str) -> anyhow::Result<()> {
    image.container().mount(keys, "/keys").run(script)
}

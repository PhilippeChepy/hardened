//! Offline PKI for `dust-api`: one ECDSA P-256 CA signing the server and client certificates.

use std::fmt::{self, Write as _};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::net::IpAddr;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, ensure};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use clap::{Subcommand, ValueEnum};
use dust_proto::Role;
use rcgen::string::Ia5String;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, SanType,
};
use time::{Duration, OffsetDateTime};

use self::Sensitivity::{Public, Secret};

pub const CA_CERT: &str = "ca.pem";
pub const CA_KEY: &str = "ca-key.pem";
pub const SERVER_CERT: &str = "server.pem";
pub const SERVER_KEY: &str = "server-key.pem";
pub const CLIENT_CERT: &str = "client.pem";
pub const CLIENT_KEY: &str = "client-key.pem";

const CA_VALIDITY_DAYS: u32 = 3650;

#[derive(Subcommand)]
pub enum Command {
    /// Creates a CA, a dust-api server certificate and an admin client certificate in DIR.
    ///
    /// DIR then works as an hctl configuration directory (--config-dir).
    Init {
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// DNS name the server certificate is valid for (repeatable).
        #[arg(long = "server-name", value_name = "NAME", required_unless_present = "server_ips")]
        server_names: Vec<ServerName>,
        /// IP address the server certificate is valid for (repeatable).
        #[arg(long = "server-ip", value_name = "IP")]
        server_ips: Vec<IpAddr>,
        /// Validity of the server and client certificates, in days.
        #[arg(long, default_value_t = 365)]
        days: u32,
    },
    /// Issues a client certificate with the CA in CA_DIR, writing it with ca.pem to DIR.
    Client {
        #[arg(long, value_enum)]
        role: RoleArg,
        /// Common name identifying the client in dust-api logs.
        #[arg(long)]
        name: String,
        /// Directory holding ca.pem and ca-key.pem.
        #[arg(long)]
        ca_dir: PathBuf,
        #[arg(long, value_name = "DIR")]
        out: PathBuf,
        /// Validity of the certificate, in days.
        #[arg(long, default_value_t = 365)]
        days: u32,
    },
    /// Prints the user-data [settings.hardened.api] section enabling dust-api with the PKI in DIR.
    UserData {
        #[arg(long)]
        dir: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum RoleArg {
    Reader,
    Admin,
}

impl From<RoleArg> for Role {
    fn from(role: RoleArg) -> Self {
        match role {
            RoleArg::Reader => Role::Reader,
            RoleArg::Admin => Role::Admin,
        }
    }
}

pub fn run(command: Command) -> anyhow::Result<()> {
    match command {
        Command::Init {
            out,
            server_names,
            server_ips,
            days,
        } => {
            let names: Vec<_> = server_names
                .into_iter()
                .chain(server_ips.into_iter().map(ServerName::Ip))
                .collect();
            init(&out, &names, days)?;
            eprintln!(
                "wrote the PKI to {dir}; enable dust-api with the output of \
                 `hctl pki user-data --dir {dir}`",
                dir = out.display()
            );
        }
        Command::Client {
            role,
            name,
            ca_dir,
            out,
            days,
        } => {
            client(&ca_dir, &out, &name, role.into(), days)?;
            eprintln!("wrote {CA_CERT}, {CLIENT_CERT} and {CLIENT_KEY} to {}", out.display());
        }
        Command::UserData { dir } => print!("{}", user_data(&dir)?),
    }
    Ok(())
}

/// A name a server certificate is valid for. Like rcgen, a value that parses as an IP address is one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerName {
    Dns(Ia5String),
    Ip(IpAddr),
}

impl FromStr for ServerName {
    type Err = rcgen::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.parse() {
            Ok(ip) => Ok(Self::Ip(ip)),
            Err(_) => s.try_into().map(Self::Dns),
        }
    }
}

impl fmt::Display for ServerName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dns(name) => f.write_str(name.as_str()),
            Self::Ip(ip) => ip.fmt(f),
        }
    }
}

impl From<ServerName> for SanType {
    fn from(name: ServerName) -> Self {
        match name {
            ServerName::Dns(name) => Self::DnsName(name),
            ServerName::Ip(ip) => Self::IpAddress(ip),
        }
    }
}

/// A certificate and its private key, PEM-encoded.
pub struct Issued {
    pub cert: String,
    pub key: String,
}

/// A certificate authority able to sign leaf certificates.
pub struct Ca {
    pub cert: String,
    issuer: Issuer<'static, KeyPair>,
}

impl Ca {
    pub fn generate() -> anyhow::Result<Self> {
        let mut params = CertificateParams::default();
        params.distinguished_name = name("hardened CA", None);
        params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        set_validity(&mut params, CA_VALIDITY_DAYS)?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key)?.pem();
        Ok(Self {
            cert,
            issuer: Issuer::new(params, key),
        })
    }

    /// Loads [`CA_CERT`] and [`CA_KEY`] from `dir`.
    pub fn load(dir: &Path) -> anyhow::Result<Self> {
        let cert = read(&dir.join(CA_CERT))?;
        let key = KeyPair::from_pem(&read(&dir.join(CA_KEY))?).context("invalid CA key")?;
        let issuer = Issuer::from_ca_cert_pem(&cert, key).context("invalid CA certificate")?;
        Ok(Self { cert, issuer })
    }

    pub fn key(&self) -> String {
        self.issuer.key().serialize_pem()
    }

    /// Issues a server certificate valid for `names` (DNS names or IP addresses).
    pub fn server(&self, names: &[ServerName], days: u32) -> anyhow::Result<Issued> {
        let common_name = names.first().context("a server certificate needs a name")?;
        let mut params = CertificateParams::default();
        params.distinguished_name = name(&common_name.to_string(), None);
        params.subject_alt_names = names.iter().cloned().map(SanType::from).collect();
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        self.sign(params, days)
    }

    /// Issues a client certificate carrying `role` in its Organization.
    pub fn client(&self, common_name: &str, role: Role, days: u32) -> anyhow::Result<Issued> {
        let org = role.organization();
        let mut params = CertificateParams::default();
        params.distinguished_name = name(common_name, Some(org));
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        self.sign(params, days)
    }

    fn sign(&self, mut params: CertificateParams, days: u32) -> anyhow::Result<Issued> {
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.use_authority_key_identifier_extension = true;
        set_validity(&mut params, days)?;
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)?;
        let cert = params.signed_by(&key, &self.issuer)?;
        Ok(Issued {
            cert: cert.pem(),
            key: key.serialize_pem(),
        })
    }
}

fn name(common_name: &str, organization: Option<&str>) -> DistinguishedName {
    let mut name = DistinguishedName::new();
    name.push(DnType::CommonName, common_name);
    if let Some(organization) = organization {
        name.push(DnType::OrganizationName, organization);
    }
    name
}

fn set_validity(params: &mut CertificateParams, days: u32) -> anyhow::Result<()> {
    let now = OffsetDateTime::now_utc();
    // Tolerate clocks running slightly behind.
    params.not_before = now - Duration::hours(1);
    params.not_after = now
        .checked_add(Duration::days(days.into()))
        .with_context(|| format!("a validity of {days} days is out of range"))?;
    Ok(())
}

fn init(dir: &Path, server_names: &[ServerName], days: u32) -> anyhow::Result<()> {
    let ca = Ca::generate()?;
    let server = ca.server(server_names, days)?;
    let admin = ca.client("admin", Role::Admin, days)?;
    write_files(
        dir,
        &[
            (CA_CERT, &ca.cert, Public),
            (CA_KEY, &ca.key(), Secret),
            (SERVER_CERT, &server.cert, Public),
            (SERVER_KEY, &server.key, Secret),
            (CLIENT_CERT, &admin.cert, Public),
            (CLIENT_KEY, &admin.key, Secret),
        ],
    )
}

fn client(ca_dir: &Path, out: &Path, common_name: &str, role: Role, days: u32) -> anyhow::Result<()> {
    let ca = Ca::load(ca_dir)?;
    let client = ca.client(common_name, role, days)?;
    write_files(
        out,
        &[
            (CA_CERT, &ca.cert, Public),
            (CLIENT_CERT, &client.cert, Public),
            (CLIENT_KEY, &client.key, Secret),
        ],
    )
}

/// The `[settings.hardened.api]` user-data section for the server certificate in `dir`.
fn user_data(dir: &Path) -> anyhow::Result<String> {
    let mut toml = String::from(
        "# dust-api TLS material. It includes the server private key: keep the user-data secret.\n\
         [settings.hardened.api]\nenabled = true\n",
    );
    for (key, file) in [
        ("client-ca", CA_CERT),
        ("certificate", SERVER_CERT),
        ("private-key", SERVER_KEY),
    ] {
        // Base64 of the PEM file, as Bottlerocket encodes PEM settings.
        let pem = read(&dir.join(file))?;
        writeln!(toml, "{key} = \"{}\"", STANDARD.encode(pem))?;
    }
    Ok(toml)
}

fn read(path: &Path) -> anyhow::Result<String> {
    std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))
}

/// Who may read a written file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Sensitivity {
    Public,
    /// Private keys: readable by their owner only.
    Secret,
}

impl Sensitivity {
    fn mode(self) -> u32 {
        match self {
            Public => 0o644,
            Secret => 0o600,
        }
    }
}

/// Writes `(name, contents, sensitivity)` files to `dir`, refusing to overwrite any existing file.
fn write_files(dir: &Path, files: &[(&str, &str, Sensitivity)]) -> anyhow::Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    for (name, _, _) in files {
        let path = dir.join(name);
        ensure!(!path.try_exists()?, "{} already exists", path.display());
    }
    for (name, contents, sensitivity) in files {
        let path = dir.join(name);
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(sensitivity.mode())
            .open(&path)
            .and_then(|mut file| file.write_all(contents.as_bytes()))
            .with_context(|| format!("writing {}", path.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::sync::Arc;

    use rustls::RootCertStore;
    use rustls::client::WebPkiServerVerifier;
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::pem::PemObject;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::server::WebPkiClientVerifier;
    use x509_parser::prelude::{FromDer, X509Certificate};

    use super::*;

    fn names(names: &[&str]) -> Vec<super::ServerName> {
        names.iter().map(|name| name.parse().unwrap()).collect()
    }

    fn der(pem: &str) -> CertificateDer<'static> {
        CertificateDer::from_pem_slice(pem.as_bytes()).unwrap()
    }

    fn roots(dir: &Path) -> Arc<RootCertStore> {
        let mut roots = RootCertStore::empty();
        roots.add(der(&read(&dir.join(CA_CERT)).unwrap())).unwrap();
        Arc::new(roots)
    }

    fn provider() -> Arc<rustls::crypto::CryptoProvider> {
        Arc::new(rustls::crypto::ring::default_provider())
    }

    /// Verifies a client certificate in `dir` against the CA in `ca_dir`, returning its role.
    fn verified_client_role(ca_dir: &Path, dir: &Path) -> Option<Role> {
        let verifier = WebPkiClientVerifier::builder_with_provider(roots(ca_dir), provider())
            .build()
            .unwrap();
        let cert = der(&read(&dir.join(CLIENT_CERT)).unwrap());
        verifier.verify_client_cert(&cert, &[], UnixTime::now()).unwrap();

        let (_, cert) = X509Certificate::from_der(&cert).unwrap();
        let org = cert.subject().iter_organization().next()?.as_str().unwrap().to_owned();
        Role::from_organization(&org)
    }

    #[test]
    fn init_creates_a_verifiable_pki() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), &names(&["node.example", "10.0.0.5"]), 30).unwrap();

        let verifier = WebPkiServerVerifier::builder_with_provider(roots(dir.path()), provider())
            .build()
            .unwrap();
        let server = der(&read(&dir.path().join(SERVER_CERT)).unwrap());
        for name in ["node.example", "10.0.0.5"] {
            let name = ServerName::try_from(name).unwrap();
            verifier
                .verify_server_cert(&server, &[], &name, &[], UnixTime::now())
                .unwrap();
        }
        let other = ServerName::try_from("other.example").unwrap();
        assert!(
            verifier
                .verify_server_cert(&server, &[], &other, &[], UnixTime::now())
                .is_err()
        );

        assert_eq!(verified_client_role(dir.path(), dir.path()), Some(Role::Admin));

        for (file, mode) in [
            (CA_KEY, 0o600),
            (SERVER_KEY, 0o600),
            (CLIENT_KEY, 0o600),
            (CA_CERT, 0o644),
        ] {
            let meta = std::fs::metadata(dir.path().join(file)).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, mode, "{file}");
        }

        let error = init(dir.path(), &names(&["node.example"]), 30).unwrap_err();
        assert!(error.to_string().contains("already exists"), "{error}");
    }

    #[test]
    fn client_signs_with_an_existing_ca() {
        let ca_dir = tempfile::tempdir().unwrap();
        init(ca_dir.path(), &names(&["127.0.0.1"]), 30).unwrap();
        let out = ca_dir.path().join("alice");
        client(ca_dir.path(), &out, "alice", Role::Reader, 30).unwrap();

        assert_eq!(verified_client_role(ca_dir.path(), &out), Some(Role::Reader));
        assert_eq!(
            read(&out.join(CA_CERT)).unwrap(),
            read(&ca_dir.path().join(CA_CERT)).unwrap()
        );
        assert!(!out.join(CA_KEY).exists());
    }

    #[test]
    fn server_names_are_dns_names_or_ips() {
        assert_eq!(
            names(&["10.0.0.5"]),
            [super::ServerName::Ip("10.0.0.5".parse().unwrap())]
        );
        assert!(
            matches!(&names(&["node.example"])[..], [super::ServerName::Dns(name)] if name.as_str() == "node.example")
        );
        assert!("nœud.example".parse::<super::ServerName>().is_err());
    }

    #[test]
    fn out_of_range_validity_is_an_error() {
        let ca = Ca::generate().unwrap();
        assert!(ca.client("alice", Role::Reader, u32::MAX).is_err());
    }

    #[test]
    fn user_data_embeds_the_server_pki() {
        let dir = tempfile::tempdir().unwrap();
        init(dir.path(), &names(&["node.example"]), 30).unwrap();

        let doc: toml::Table = user_data(dir.path()).unwrap().parse().unwrap();
        let api = &doc["settings"]["hardened"]["api"];
        assert_eq!(api["enabled"].as_bool(), Some(true));
        for (key, file) in [
            ("client-ca", CA_CERT),
            ("certificate", SERVER_CERT),
            ("private-key", SERVER_KEY),
        ] {
            assert_eq!(
                STANDARD.decode(api[key].as_str().unwrap()).unwrap(),
                read(&dir.path().join(file)).unwrap().into_bytes(),
                "{key}"
            );
        }
    }
}

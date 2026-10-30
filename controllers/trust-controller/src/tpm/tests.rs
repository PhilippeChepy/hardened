//! [`Tpm`] against a scripted transport, and against `swtpm` (ignored by default).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use super::*;
use crate::marshal;
use crate::marshal::Writer;

/// Replays canned responses and records the commands it was sent.
#[derive(Clone, Default)]
struct Scripted(Arc<Mutex<Script>>);

#[derive(Default)]
struct Script {
    responses: VecDeque<Vec<u8>>,
    commands: Vec<Vec<u8>>,
}

impl Scripted {
    fn new(responses: impl IntoIterator<Item = Vec<u8>>) -> Self {
        let script = Script {
            responses: responses.into_iter().collect(),
            commands: Vec::new(),
        };
        Self(Arc::new(Mutex::new(script)))
    }

    fn commands(&self) -> Vec<Vec<u8>> {
        self.0.lock().unwrap().commands.clone()
    }
}

impl Transport for Scripted {
    fn transact(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
        let mut script = self.0.lock().unwrap();
        script.commands.push(command.to_vec());
        script
            .responses
            .pop_front()
            .ok_or_else(|| io::Error::other("unexpected command"))
    }
}

fn error_response(rc: u32) -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(0x8001).u32(10).u32(rc);
    w.into_bytes()
}

fn selection(w: &mut Writer, hash: u16, mask: u32) {
    w.u32(1).u16(hash).u8(3).bytes(&mask.to_le_bytes()[..3]);
}

/// A TPM2_PCR_Read response where PCR `i` has the digest `[i + fill; 32]`.
fn pcr_read_response(update_counter: u32, mask: u32, fill: u8) -> Vec<u8> {
    let mut w = Writer::default();
    w.u32(update_counter);
    selection(&mut w, 0x000b, mask);
    w.u32(mask.count_ones());
    for index in (PcrSelection { hash: 0, mask }).indices() {
        w.tpm2b(&[index as u8 + fill; 32]);
    }
    marshal::test_response(&[], &w.into_bytes(), false)
}

fn pcr_values(mask: u32, fill: u8) -> Vec<(u32, Vec<u8>)> {
    PcrSelection { hash: 0, mask }
        .indices()
        .map(|i| (i, vec![i as u8 + fill; 32]))
        .collect()
}

/// The `pcrSelect` bytes of a TPM2_PCR_Read command.
fn read_selection(command: &[u8]) -> &[u8] {
    &command[14..]
}

#[test]
fn pcr_read_completes_partial_selections() {
    let transport = Scripted::new([
        pcr_read_response(7, 0x0ff, 0),
        pcr_read_response(7, 0xf00, 0),
    ]);
    let mut tpm = Tpm::with_transport(transport.clone());
    let pcrs: Vec<u32> = (0..12).rev().collect();
    assert_eq!(
        tpm.pcr_read(HashAlg::Sha256, &pcrs).unwrap(),
        pcr_values(0xfff, 0)
    );
    let commands = transport.commands();
    assert_eq!(read_selection(&commands[0]), [0, 0x0b, 3, 0xff, 0x0f, 0]);
    assert_eq!(read_selection(&commands[1]), [0, 0x0b, 3, 0, 0x0f, 0]);
    assert_eq!(commands.len(), 2);
}

#[test]
fn pcr_read_restarts_when_pcrs_are_extended_in_between() {
    let transport = Scripted::new([
        pcr_read_response(1, 0x0ff, 0),
        pcr_read_response(2, 0xf00, 9),
        pcr_read_response(2, 0x0ff, 9),
        pcr_read_response(2, 0xf00, 9),
    ]);
    let mut tpm = Tpm::with_transport(transport.clone());
    let pcrs: Vec<u32> = (0..12).collect();
    assert_eq!(
        tpm.pcr_read(HashAlg::Sha256, &pcrs).unwrap(),
        pcr_values(0xfff, 9)
    );
    assert_eq!(
        read_selection(&transport.commands()[2]),
        [0, 0x0b, 3, 0xff, 0x0f, 0]
    );
}

#[test]
fn pcr_read_deduplicates_and_validates_indices() {
    let transport = Scripted::new([pcr_read_response(0, 0x81, 0)]);
    let mut tpm = Tpm::with_transport(transport.clone());
    assert!(matches!(
        tpm.pcr_read(HashAlg::Sha256, &[3, 24]),
        Err(TpmError::InvalidPcr(24))
    ));
    assert!(tpm.pcr_read(HashAlg::Sha256, &[]).unwrap().is_empty());
    assert!(transport.commands().is_empty());
    assert_eq!(
        tpm.pcr_read(HashAlg::Sha256, &[7, 0, 7]).unwrap(),
        pcr_values(0x81, 0)
    );
    assert_eq!(
        read_selection(&transport.commands()[0]),
        [0, 0x0b, 3, 0x81, 0, 0]
    );
}

#[test]
fn pcr_read_reports_unavailable_banks() {
    let mut w = Writer::default();
    w.u32(0).u32(0).u32(0); // pcrUpdateCounter, no selection, no digest
    let transport = Scripted::new([marshal::test_response(&[], &w.into_bytes(), false)]);
    let mut tpm = Tpm::with_transport(transport);
    let err = tpm.pcr_read(HashAlg::Sha384, &[4]).unwrap_err();
    assert!(matches!(
        err,
        TpmError::PcrUnavailable {
            bank: HashAlg::Sha384,
            pcr: 4
        }
    ));
}

#[test]
fn pcr_read_rejects_digests_of_another_size() {
    let mut w = Writer::default();
    w.u32(0);
    selection(&mut w, 0x000b, 1);
    w.u32(1).tpm2b(&[0; 20]);
    let transport = Scripted::new([marshal::test_response(&[], &w.into_bytes(), false)]);
    let mut tpm = Tpm::with_transport(transport);
    assert!(matches!(
        tpm.pcr_read(HashAlg::Sha256, &[0]),
        Err(TpmError::Malformed(_))
    ));
}

#[test]
fn tpm_errors_are_surfaced_and_busy_tpms_retried() {
    let transport = Scripted::new([
        error_response(0x922),
        pcr_read_response(0, 1, 0),
        error_response(0x9a2),
    ]);
    let mut tpm = Tpm::with_transport(transport.clone());
    assert_eq!(
        tpm.pcr_read(HashAlg::Sha256, &[0]).unwrap(),
        pcr_values(1, 0)
    );
    assert_eq!(transport.commands().len(), 2);
    let err = tpm.pcr_read(HashAlg::Sha256, &[0]).unwrap_err();
    assert!(matches!(err, TpmError::Response(ResponseCode(0x9a2))));
}

const AK_HANDLE: u32 = 0x8000_0000;

fn create_primary_response() -> Vec<u8> {
    let mut w = Writer::default();
    w.tpm2b(&commands::ak_template());
    marshal::test_response(&[AK_HANDLE], &w.into_bytes(), true)
}

fn ak_qualified_name() -> Vec<u8> {
    let name = [&[0x00, 0x0b][..], &Sha256::digest(commands::ak_template())].concat();
    let qualified = Sha256::new()
        .chain_update([0x40, 0, 0, 0x0b])
        .chain_update(name)
        .finalize();
    [&[0x00, 0x0b][..], &qualified].concat()
}

fn attest(nonce: &[u8], mask: u32, pcrs: &[(u32, Vec<u8>)]) -> Vec<u8> {
    let digest = pcr_digest(pcrs);
    let mut w = Writer::default();
    w.u32(0xff54_4347)
        .u16(0x8018)
        .tpm2b(&ak_qualified_name())
        .tpm2b(nonce)
        .bytes(&[0; 25]);
    selection(&mut w, 0x000b, mask);
    w.tpm2b(&digest);
    w.into_bytes()
}

fn signature() -> Vec<u8> {
    let mut w = Writer::default();
    w.u16(0x0018).u16(0x000b).tpm2b(&[1; 32]).tpm2b(&[2; 32]);
    w.into_bytes()
}

fn quote_response(attest: &[u8]) -> Vec<u8> {
    let mut w = Writer::default();
    w.tpm2b(attest).bytes(&signature());
    marshal::test_response(&[], &w.into_bytes(), true)
}

fn flush_response() -> Vec<u8> {
    marshal::test_response(&[], &[], false)
}

#[test]
fn quote_returns_consistent_evidence_and_flushes_the_key() {
    let mask = 0b1000_0011;
    let attest = attest(b"nonce", mask, &pcr_values(mask, 0));
    let transport = Scripted::new([
        create_primary_response(),
        quote_response(&attest),
        pcr_read_response(0, mask, 0),
        flush_response(),
    ]);
    let mut tpm = Tpm::with_transport(transport.clone());
    let quote = tpm.quote(b"nonce", HashAlg::Sha256, &[7, 1, 0]).unwrap();
    assert_eq!(quote.attest, attest);
    assert_eq!(quote.signature, signature());
    assert_eq!(quote.ak_public, commands::ak_template());
    assert_eq!(quote.pcrs, pcr_values(mask, 0));
    assert_eq!(
        tpm.attestation_key().unwrap().public,
        commands::ak_template()
    );
    drop(tpm);

    let sent = transport.commands();
    assert_eq!(
        sent[0],
        commands::create_primary(commands::RH_ENDORSEMENT, &commands::ak_template())
    );
    assert_eq!(
        sent[1],
        commands::quote(AK_HANDLE, b"nonce", PcrSelection { hash: 0x000b, mask })
    );
    assert_eq!(sent[3], commands::flush_context(AK_HANDLE));
}

#[test]
fn quote_is_retaken_when_pcrs_change_before_being_read() {
    let mask = 0b1;
    let transport = Scripted::new([
        create_primary_response(),
        quote_response(&attest(b"", mask, &pcr_values(mask, 0))),
        pcr_read_response(0, mask, 5),
        quote_response(&attest(b"", mask, &pcr_values(mask, 5))),
        pcr_read_response(0, mask, 5),
        flush_response(),
    ]);
    let mut tpm = Tpm::with_transport(transport.clone());
    assert_eq!(
        tpm.quote(b"", HashAlg::Sha256, &[0]).unwrap().pcrs,
        pcr_values(mask, 5)
    );
}

#[test]
fn quote_validates_its_inputs_and_the_attestation() {
    let mut tpm = Tpm::with_transport(Scripted::default());
    let err = tpm.quote(&[0; 65], HashAlg::Sha256, &[0]).unwrap_err();
    assert!(matches!(err, TpmError::NonceTooLong(65)));
    assert!(matches!(
        tpm.quote(b"", HashAlg::Sha256, &[99]),
        Err(TpmError::InvalidPcr(99))
    ));

    let transport = Scripted::new([
        create_primary_response(),
        quote_response(&attest(b"replayed", 1, &pcr_values(1, 0))),
        flush_response(),
    ]);
    let mut tpm = Tpm::with_transport(transport);
    assert!(matches!(
        tpm.quote(b"fresh", HashAlg::Sha256, &[0]),
        Err(TpmError::Malformed(_))
    ));
}

const SRK_HANDLE: u32 = 0x8000_0000;
const OBJECT_HANDLE: u32 = 0x8000_0001;
const SESSION_HANDLE: u32 = 0x0300_0000;

fn srk_response() -> Vec<u8> {
    let mut w = Writer::default();
    w.tpm2b(&commands::srk_template());
    marshal::test_response(&[SRK_HANDLE], &w.into_bytes(), true)
}

fn sealed() -> Sealed {
    Sealed {
        private: b"private".to_vec(),
        public: b"public".to_vec(),
    }
}

#[test]
fn pcr_policy_is_computed_from_the_current_values() {
    let transport = Scripted::new([pcr_read_response(0, 1 << 11, 0)]);
    let mut tpm = Tpm::with_transport(transport.clone());
    let policy = tpm.pcr_policy(&[11]).unwrap();
    let pcr11 = PcrSelection {
        hash: 0x000b,
        mask: 1 << 11,
    };
    assert_eq!(
        policy,
        commands::policy_pcr_digest(pcr11, &Sha256::digest([11; 32]))
    );
    assert_eq!(
        read_selection(&transport.commands()[0]),
        [0, 0x0b, 3, 0, 0x08, 0]
    );
}

#[test]
fn seal_creates_a_policy_bound_object_under_the_storage_key() {
    let mut created = Writer::default();
    created.tpm2b(b"private").tpm2b(b"public").bytes(&[0; 10]);
    let transport = Scripted::new([
        srk_response(),
        marshal::test_response(&[], &created.into_bytes(), true),
        flush_response(),
    ]);
    let mut tpm = Tpm::with_transport(transport.clone());
    assert_eq!(tpm.seal(b"secret", &[0xab; 32]).unwrap(), sealed());
    let sent = transport.commands();
    assert_eq!(
        sent,
        [
            commands::create_primary(commands::RH_OWNER, &commands::srk_template()),
            commands::create(
                SRK_HANDLE,
                b"secret",
                &commands::sealed_template(&[0xab; 32])
            ),
            commands::flush_context(SRK_HANDLE),
        ]
    );
}

/// The responses to an unseal up to TPM2_Unseal, which answers `unsealed`.
fn unseal_script(unsealed: Vec<u8>) -> Vec<Vec<u8>> {
    let mut name = Writer::default();
    name.tpm2b(b"name");
    let mut nonce = Writer::default();
    nonce.tpm2b(&[9; 16]);
    vec![
        srk_response(),
        marshal::test_response(&[OBJECT_HANDLE], &name.into_bytes(), true),
        flush_response(),
        marshal::test_response(&[SESSION_HANDLE], &nonce.into_bytes(), false),
        marshal::test_response(&[], &[], false),
        unsealed,
    ]
}

#[test]
fn unseal_satisfies_the_pcr_policy_and_flushes_everything() {
    let mut data = Writer::default();
    data.tpm2b(b"secret");
    let mut script = unseal_script(marshal::test_response(&[], &data.into_bytes(), true));
    script.push(flush_response());
    let transport = Scripted::new(script);
    let mut tpm = Tpm::with_transport(transport.clone());
    assert_eq!(&**tpm.unseal(&sealed(), &[11]).unwrap(), b"secret");

    let sent = transport.commands();
    assert_eq!(sent.len(), 7);
    assert_eq!(sent[1], commands::load(SRK_HANDLE, b"private", b"public"));
    assert_eq!(sent[2], commands::flush_context(SRK_HANDLE));
    assert_eq!(sent[3][..10], [0x80, 0x01, 0, 0, 0, 0x2b, 0, 0, 0x01, 0x76]);
    let pcr11 = PcrSelection {
        hash: 0x000b,
        mask: 1 << 11,
    };
    assert_eq!(sent[4], commands::policy_pcr(SESSION_HANDLE, pcr11));
    // TPM2_Unseal of the object, in the policy session (whose nonce is random).
    assert_eq!(sent[5][6..14], [0, 0, 0x01, 0x5e, 0x80, 0, 0, 1]);
    assert_eq!(sent[5][18..22], SESSION_HANDLE.to_be_bytes());
    assert_eq!(sent[6], commands::flush_context(OBJECT_HANDLE));
}

#[test]
fn a_failed_unseal_flushes_its_session() {
    let mut script = unseal_script(error_response(0x99d));
    script.extend([flush_response(), flush_response()]);
    let transport = Scripted::new(script);
    let mut tpm = Tpm::with_transport(transport.clone());
    let err = tpm.unseal(&sealed(), &[11]).unwrap_err();
    assert!(err.is_sealed_elsewhere(), "{err}");
    let sent = transport.commands();
    assert_eq!(sent[6], commands::flush_context(SESSION_HANDLE));
    assert_eq!(sent[7], commands::flush_context(OBJECT_HANDLE));

    // A blob of another TPM does not load: nothing else is sent.
    let transport = Scripted::new([srk_response(), error_response(0x1df), flush_response()]);
    let mut tpm = Tpm::with_transport(transport.clone());
    assert!(
        tpm.unseal(&sealed(), &[11])
            .unwrap_err()
            .is_sealed_elsewhere()
    );
    assert_eq!(transport.commands().len(), 3);
    assert!(!TpmError::Response(ResponseCode(0x902)).is_sealed_elsewhere());
}

/// End-to-end against `swtpm` (from `$SWTPM` or `PATH`), e.g. in `controllers/`:
/// `nix shell nixpkgs#swtpm -c cargo test -p trust-controller swtpm -- --ignored`.
mod swtpm {
    use std::net::{Ipv4Addr, TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Instant;

    use super::*;

    /// Raw TPM commands over a stream (swtpm's data channel).
    struct Stream(TcpStream);

    impl Transport for Stream {
        fn transact(&mut self, command: &[u8]) -> io::Result<Vec<u8>> {
            use std::io::{Read as _, Write as _};

            self.0.write_all(command)?;
            let mut response = vec![0; marshal::HEADER_LEN];
            self.0.read_exact(&mut response)?;
            let size = u32::from_be_bytes(response[2..6].try_into().unwrap()) as usize;
            response.resize(size, 0);
            self.0.read_exact(&mut response[marshal::HEADER_LEN..])?;
            Ok(response)
        }
    }

    struct Swtpm {
        child: Child,
        port: u16,
        _state: tempfile::TempDir,
    }

    impl Swtpm {
        fn spawn() -> Self {
            let state = tempfile::tempdir().unwrap();
            let [port, ctrl] = [(); 2].map(|()| {
                let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
                listener.local_addr().unwrap().port()
            });
            let child = Command::new(std::env::var_os("SWTPM").unwrap_or("swtpm".into()))
                .args(["socket", "--tpm2", "--flags", "not-need-init,startup-clear"])
                .arg("--tpmstate")
                .arg(format!("dir={}", state.path().display()))
                .arg("--server")
                .arg(format!("type=tcp,port={port},bindaddr=127.0.0.1"))
                .arg("--ctrl")
                .arg(format!("type=tcp,port={ctrl},bindaddr=127.0.0.1"))
                .stdin(Stdio::null())
                .spawn()
                .expect("spawning swtpm");
            Self {
                child,
                port,
                _state: state,
            }
        }

        fn connect(&self) -> Tpm {
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match TcpStream::connect((Ipv4Addr::LOCALHOST, self.port)) {
                    Ok(stream) => return Tpm::with_transport(Stream(stream)),
                    Err(e) if Instant::now() > deadline => panic!("connecting to swtpm: {e}"),
                    Err(_) => thread::sleep(Duration::from_millis(50)),
                }
            }
        }
    }

    impl Drop for Swtpm {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// TPM2_VerifySignature of `attest` with the loaded attestation key.
    fn verify(tpm: &mut Tpm, attest: &[u8], signature: &[u8]) -> Result<(), TpmError> {
        let handle = tpm.attestation_key()?.handle;
        let command = marshal::command(0x177, &[handle], marshal::Auth::None, |w| {
            w.tpm2b(&Sha256::digest(attest)).bytes(signature);
        });
        let response = tpm.execute(&command)?;
        marshal::response(&response, 0).map(drop)
    }

    #[test]
    #[ignore = "needs swtpm"]
    fn end_to_end() {
        let swtpm = Swtpm::spawn();
        let mut tpm = swtpm.connect();

        let all: Vec<u32> = (0..24).collect();
        for bank in [HashAlg::Sha1, HashAlg::Sha256, HashAlg::Sha384] {
            let values = tpm.pcr_read(bank, &all).unwrap();
            assert_eq!(values.iter().map(|(i, _)| *i).collect::<Vec<_>>(), all);
            assert!(values.iter().all(|(_, v)| v.len() == bank.digest_len()));
        }

        let quote = tpm.quote(b"verifier nonce", HashAlg::Sha256, &all).unwrap();
        assert_eq!(quote.pcrs.len(), 24);
        verify(&mut tpm, &quote.attest, &quote.signature).unwrap();
        // What a remote verifier checks, without the TPM.
        let response = trust_controller::attestation::QuoteResponse {
            attest: quote.attest.clone(),
            signature: quote.signature.clone(),
            ak_public: quote.ak_public.clone(),
            values: quote
                .pcrs
                .iter()
                .map(|(index, digest)| trust_controller::attestation::PcrValue {
                    index: *index,
                    digest: digest.clone(),
                })
                .collect(),
        };
        let sha256 = trust_controller::attestation::HashAlgorithm::Sha256;
        let verified =
            trust_controller::quote_verification::verify(&response, b"verifier nonce", sha256)
                .unwrap();
        assert_eq!(verified.pcrs.len(), 24);
        let mut forged = quote.attest.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(matches!(
            verify(&mut tpm, &forged, &quote.signature),
            Err(TpmError::Response(_))
        ));

        let sha1_quote = tpm
            .quote(&[7; MAX_NONCE_LEN], HashAlg::Sha1, &[0, 7, 23])
            .unwrap();
        verify(&mut tpm, &sha1_quote.attest, &sha1_quote.signature).unwrap();
        drop(tpm);

        // The primary key is derived from the endorsement seed: same key in a new session.
        let mut tpm = swtpm.connect();
        assert_eq!(tpm.attestation_key().unwrap().public, quote.ak_public);
    }

    /// The policy digest a trial session computes for PolicyPCR over the current values.
    fn trial_policy(tpm: &mut Tpm, selection: PcrSelection) -> Vec<u8> {
        const SE_TRIAL: u8 = 0x03;
        let command = marshal::command(
            0x176,
            &[0x4000_0007, 0x4000_0007],
            marshal::Auth::None,
            |w| {
                w.tpm2b(&[1; 16])
                    .tpm2b(&[])
                    .u8(SE_TRIAL)
                    .u16(0x0010)
                    .u16(0x000b);
            },
        );
        let session = commands::parse_handle(&tpm.execute(&command).unwrap()).unwrap();
        commands::parse_empty(
            &tpm.execute(&commands::policy_pcr(session, selection))
                .unwrap(),
        )
        .unwrap();
        let command = marshal::command(0x189, &[session], marshal::Auth::None, |_| {});
        let response = tpm.execute(&command).unwrap();
        let digest = marshal::response(&response, 0)
            .unwrap()
            .params
            .tpm2b()
            .unwrap()
            .to_vec();
        tpm.flush(session);
        digest
    }

    fn extend(tpm: &mut Tpm, pcr: u32) {
        let command = marshal::command(0x182, &[pcr], marshal::Auth::EmptyPassword, |w| {
            w.u32(1).u16(0x000b).bytes(&[0x42; 32]);
        });
        marshal::response(&tpm.execute(&command).unwrap(), 0).unwrap();
    }

    #[test]
    #[ignore = "needs swtpm"]
    fn seals_to_pcr_11() {
        let pcr11 = PcrSelection {
            hash: 0x000b,
            mask: 1 << 11,
        };
        let swtpm = Swtpm::spawn();
        let mut tpm = swtpm.connect();
        let policy = tpm.pcr_policy(&[11]).unwrap();
        assert_eq!(trial_policy(&mut tpm, pcr11), policy);
        assert_eq!(
            hex::encode(policy),
            "fd32fa22c52cfc8e1a0c29eb38519f87084cab0b04b0d8f020a4d38b2f4e223e",
            "PCR 11 of a fresh TPM is zeros"
        );

        let sealed = tpm.seal(b"256 bits of secret", &policy).unwrap();
        assert_eq!(
            &**tpm.unseal(&sealed, &[11]).unwrap(),
            b"256 bits of secret"
        );
        drop(tpm);
        // The storage key is derived from the owner seed: the blob loads in a new session.
        let mut tpm = swtpm.connect();
        assert_eq!(
            &**tpm.unseal(&sealed, &[11]).unwrap(),
            b"256 bits of secret"
        );

        let mut tampered = sealed.clone();
        *tampered.private.last_mut().unwrap() ^= 1;
        let err = tpm.unseal(&tampered, &[11]).unwrap_err();
        assert!(err.is_sealed_elsewhere(), "{err}");

        extend(&mut tpm, 11);
        assert_ne!(tpm.pcr_policy(&[11]).unwrap(), policy);
        assert_eq!(
            trial_policy(&mut tpm, pcr11),
            tpm.pcr_policy(&[11]).unwrap()
        );
        let err = tpm.unseal(&sealed, &[11]).unwrap_err();
        assert!(err.is_sealed_elsewhere(), "{err}");

        // Another TPM: its own owner seed.
        let other = Swtpm::spawn();
        let mut tpm = other.connect();
        let err = tpm.unseal(&sealed, &[11]).unwrap_err();
        assert!(err.is_sealed_elsewhere(), "{err}");
    }
}

//! dust-ntp: keeps the clock in sync with NTP servers (see the library docs).

use std::collections::BTreeSet;
use std::io::{self, IsTerminal};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;
use dust_ntp::clock::{self, Correction, MIN_POLL};
use dust_ntp::packet::{self, Nanos, Rejected, Reply, Sample};
use dust_ntp::{Measurement, Status};
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about = "SNTP client keeping the clock in sync")]
struct Cli {
    /// A server to query: a host name or an address. Repeated, in order of preference.
    #[arg(long = "server", required = true)]
    servers: Vec<String>,
    /// Where to write the status, as JSON.
    #[arg(long)]
    status: PathBuf,
}

/// How long to wait for a reply.
const TIMEOUT: Duration = Duration::from_secs(2);
/// Addresses queried per server name (a pool name resolves to several).
const ADDRESSES_PER_SERVER: usize = 4;

fn main() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let logs = tracing_subscriber::fmt()
        .with_writer(io::stderr)
        .with_env_filter(filter);
    if io::stderr().is_terminal() {
        logs.init();
    } else {
        // Run by dust-init, which timestamps the lines it forwards to its own log.
        logs.with_ansi(false).without_time().with_target(false).init();
    }
    let cli = Cli::parse();
    info!(servers = ?cli.servers, "started");

    let mut client = Client::new(cli.servers);
    loop {
        client.round();
        if let Err(e) = client.status.write(&cli.status) {
            warn!("cannot write the status to {}: {e}", cli.status.display());
        }
        std::thread::sleep(Duration::from_secs(1 << client.poll));
    }
}

struct Client {
    servers: Vec<String>,
    /// The poll interval, as a power of two seconds.
    poll: u32,
    /// Whether the last round corrected the clock.
    in_sync: bool,
    /// Addresses that told us to go away (`DENY`, `RSTR`).
    denied: BTreeSet<SocketAddr>,
    status: Status,
}

/// A usable reply.
struct Candidate {
    server: String,
    address: SocketAddr,
    reply: Reply,
    sample: Sample,
}

impl Candidate {
    /// The error bound of the time it gives: the server's own, plus half the round trip.
    fn distance(&self) -> Duration {
        self.reply.root_distance() + half_delay(&self.sample)
    }
}

impl Client {
    fn new(servers: Vec<String>) -> Self {
        Self {
            status: Status {
                servers: servers.clone(),
                ..Status::default()
            },
            servers,
            poll: MIN_POLL,
            in_sync: false,
            denied: BTreeSet::new(),
        }
    }

    /// Queries every server, then corrects the clock with the best reply.
    fn round(&mut self) {
        match self.best() {
            Ok(best) => self.correct(&best),
            Err(e) => {
                if self.in_sync || self.status.last.is_none() && self.status.error.is_none() {
                    warn!("no usable reply, the clock is not corrected: {e}");
                } else {
                    debug!("no usable reply: {e}");
                }
                self.in_sync = false;
                self.status.error = Some(e);
                self.poll = self.poll.saturating_sub(1).max(MIN_POLL);
            }
        }
        self.status.poll_seconds = 1 << self.poll;
    }

    /// The reply closest to its reference clock, or why there is none.
    fn best(&mut self) -> Result<Candidate, String> {
        let mut errors = Vec::new();
        let mut best: Option<Candidate> = None;
        for (server, address) in self.addresses(&mut errors) {
            match query(address) {
                Ok((reply, sample)) => {
                    let candidate = Candidate {
                        server,
                        address,
                        reply,
                        sample,
                    };
                    if best.as_ref().is_none_or(|best| candidate.distance() < best.distance()) {
                        best = Some(candidate);
                    }
                }
                Err(e) => {
                    if let Failure::Rejected(Rejected::Kiss(code)) = &e {
                        match code {
                            b"RATE" => self.poll = (self.poll + 1).min(clock::MAX_POLL),
                            b"DENY" | b"RSTR" => {
                                self.denied.insert(address);
                            }
                            _ => {}
                        }
                    }
                    errors.push(format!("{server} ({address}): {e}"));
                }
            }
        }
        best.ok_or_else(|| match errors.is_empty() {
            true => "no server address".to_owned(),
            false => errors.join("; "),
        })
    }

    /// The addresses to query, each with its server's name.
    fn addresses(&self, errors: &mut Vec<String>) -> Vec<(String, SocketAddr)> {
        let mut addresses: Vec<(String, SocketAddr)> = Vec::new();
        for server in &self.servers {
            let resolved: Vec<SocketAddr> = match server.parse::<IpAddr>() {
                Ok(ip) => vec![SocketAddr::new(ip, packet::PORT)],
                Err(_) => match (server.as_str(), packet::PORT).to_socket_addrs() {
                    Ok(resolved) => resolved.collect(),
                    Err(e) => {
                        errors.push(format!("{server}: {e}"));
                        continue;
                    }
                },
            };
            let usable = resolved
                .into_iter()
                .filter(|address| !self.denied.contains(address))
                .take(ADDRESSES_PER_SERVER);
            for address in usable {
                if !addresses.iter().any(|(_, known)| *known == address) {
                    addresses.push((server.clone(), address));
                }
            }
        }
        addresses
    }

    fn correct(&mut self, best: &Candidate) {
        let correction = Correction::for_offset(best.sample.offset);
        let (max_error, estimated_error) = (best.distance(), half_delay(&best.sample));
        let corrected = match correction {
            Correction::Step(offset) => {
                clock::step(offset).and_then(|()| clock::slew(0, MIN_POLL, max_error, estimated_error))
            }
            Correction::Slew(offset) => clock::slew(offset, self.poll, max_error, estimated_error),
        };
        let offset_ms = format!("{:+.3}", best.sample.offset as f64 / 1e6);
        let delay_ms = format!("{:.3}", best.sample.delay as f64 / 1e6);
        let (server, address, stratum) = (&best.server, best.address, best.reply.stratum);
        if let Err(e) = corrected {
            error!(server, %address, offset_ms, "cannot correct the clock: {e}");
            self.in_sync = false;
            self.status.error = Some(format!("cannot correct the clock: {e}"));
            return;
        }
        if let Correction::Step(_) = correction {
            warn!(server, %address, offset_ms, "clock stepped");
        }
        if self.in_sync {
            debug!(server, %address, stratum, offset_ms, delay_ms, "clock corrected");
        } else {
            info!(server, %address, stratum, offset_ms, delay_ms, "clock synchronized");
        }
        self.in_sync = true;
        self.poll = clock::next_poll(self.poll, correction);
        self.status.error = None;
        self.status.last = Some(Measurement {
            server: best.server.clone(),
            address: best.address.to_string(),
            stratum,
            reference: best.reply.reference_id(),
            offset_ns: best.sample.offset,
            delay_ns: best.sample.delay,
            stepped: matches!(correction, Correction::Step(_)),
            at_unix_ns: now(),
        });
    }
}

#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("no reply within {TIMEOUT:?}")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rejected(#[from] Rejected),
}

/// Sends a request to `address` and waits for its reply, ignoring datagrams that do not answer it.
fn query(address: SocketAddr) -> Result<(Reply, Sample), Failure> {
    let local: SocketAddr = match address {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local)?;
    socket.connect(address)?;
    let mut cookie = [0; 8];
    rustix::rand::getrandom(&mut cookie, rustix::rand::GetRandomFlags::empty()).map_err(io::Error::from)?;

    let deadline = Instant::now() + TIMEOUT;
    let sent = now();
    socket.send(&packet::request(cookie))?;
    let mut buffer = [0; 1024];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Failure::Timeout);
        }
        socket.set_read_timeout(Some(remaining))?;
        let length = match socket.recv(&mut buffer) {
            Ok(length) => length,
            Err(e) if matches!(e.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut) => {
                return Err(Failure::Timeout);
            }
            Err(e) => return Err(e.into()),
        };
        let received = now();
        match Reply::parse(&buffer[..length], cookie) {
            Ok(reply) => {
                let sample = Sample::new(&reply, sent, received);
                return Ok((reply, sample));
            }
            Err(Rejected::Unexpected) => continue,
            Err(e) => return Err(e.into()),
        }
    }
}

fn half_delay(sample: &Sample) -> Duration {
    Duration::from_nanos(sample.delay.unsigned_abs() / 2)
}

fn now() -> Nanos {
    let since_epoch = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    since_epoch.as_nanos().try_into().unwrap_or(Nanos::MAX)
}

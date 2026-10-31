//! The SNTP client: a round resolves every server and queries every address at once, then
//! corrects the clock with the best reply. A round with unresponsive servers takes one
//! [`TIMEOUT`] (plus the resolution's).

use std::collections::BTreeSet;
use std::io;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::time::Duration;

use controllers_helpers::NonEmpty;
use rustix::rand::GetRandomFlags;
use time_controller::TimeServer;
use tokio::net::UdpSocket;

use crate::clock;
use crate::clock::Correction;
use crate::clock::MIN_POLL;
use crate::clock::now;
use crate::measurement::Measurement;
use crate::measurement::Source;
use crate::packet;
use crate::packet::Nanos;
use crate::packet::Rejected;
use crate::packet::Reply;
use crate::packet::Sample;

/// How long to wait for a reply.
const TIMEOUT: Duration = Duration::from_secs(2);
/// Addresses queried per server name (a pool name resolves to several).
const ADDRESSES_PER_SERVER: usize = 4;

/// The client's state across rounds.
pub struct Client {
    /// The poll interval, as a power of two seconds.
    pub poll: u32,
    /// The servers it queries, in order of preference.
    servers: NonEmpty<TimeServer>,
    /// The port it queries them on: [`packet::PORT`] but in tests.
    port: u16,
    /// Addresses that told us to go away (`DENY`, `RSTR`).
    denied: BTreeSet<SocketAddr>,
    /// Whether the last round corrected the clock; `None` before the first. Only for the logs:
    /// changes are logged louder.
    corrected: Option<bool>,
}

/// An address to query, and the server it comes from.
struct ServerAddress {
    server: TimeServer,
    address: SocketAddr,
}

/// A usable reply.
struct Candidate {
    server: TimeServer,
    address: SocketAddr,
    reply: Reply,
    sample: Sample,
}

impl Candidate {
    /// The error bound of the time it gives: the server's own, plus half the round trip.
    #[must_use]
    fn distance(&self) -> Duration {
        self.reply.root_distance() + self.sample.delay / 2
    }
}

impl Client {
    /// A client of `servers`, in order of preference, polling as often as it may.
    #[must_use]
    pub fn new(servers: NonEmpty<TimeServer>) -> Self {
        Self {
            poll: MIN_POLL,
            servers,
            port: packet::PORT,
            denied: BTreeSet::new(),
            corrected: None,
        }
    }

    /// Queries every server, then corrects the clock with the best reply: returns the
    /// correction, or why there is none.
    pub async fn round(&mut self) -> Result<Measurement, String> {
        let result = match self.best().await {
            Ok(best) => self.correct(&best),
            Err(e) => {
                if self.corrected == Some(false) {
                    tracing::debug!(error = %e, "no usable reply");
                } else {
                    tracing::warn!(error = %e, "no usable reply, the clock is not corrected");
                }
                self.poll = self.poll.saturating_sub(1).max(MIN_POLL);
                Err(e)
            }
        };
        self.corrected = Some(result.is_ok());
        result
    }

    /// The reply closest to its reference clock, or why there is none.
    async fn best(&mut self) -> Result<Candidate, String> {
        let mut errors = Vec::new();
        let addresses = self.addresses(&mut errors).await;
        let replies = join_ordered(addresses.iter().map(|known| query(known.address))).await;
        let mut best: Option<Candidate> = None;
        for (ServerAddress { server, address }, reply) in addresses.into_iter().zip(replies) {
            match reply {
                Ok((reply, sample)) => {
                    let candidate = Candidate {
                        server,
                        address,
                        reply,
                        sample,
                    };
                    if best
                        .as_ref()
                        .is_none_or(|best| candidate.distance() < best.distance())
                    {
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
        match best {
            Some(best) => Ok(best),
            None if errors.is_empty() => Err("no server address".to_owned()),
            None => Err(errors.join("; ")),
        }
    }

    /// The addresses to query, each with its server's name. The servers are resolved
    /// concurrently, each on one of tokio's blocking threads (musl's `getaddrinfo`).
    async fn addresses(&self, errors: &mut Vec<String>) -> Vec<ServerAddress> {
        let port = self.port;
        let resolutions = join_ordered(self.servers.iter().map(|server| {
            let server = server.clone();
            async move { resolve(&server, port).await }
        }))
        .await;
        let mut addresses: Vec<ServerAddress> = Vec::new();
        for (server, resolved) in self.servers.iter().zip(resolutions) {
            let resolved = match resolved {
                Ok(resolved) => resolved,
                Err(e) => {
                    errors.push(format!("{server}: {e}"));
                    continue;
                }
            };
            let usable = resolved
                .into_iter()
                .filter(|address| !self.denied.contains(address))
                .take(ADDRESSES_PER_SERVER);
            for address in usable {
                if !addresses.iter().any(|known| known.address == address) {
                    addresses.push(ServerAddress {
                        server: server.clone(),
                        address,
                    });
                }
            }
        }
        addresses
    }

    fn correct(&mut self, best: &Candidate) -> Result<Measurement, String> {
        let correction = Correction::for_offset(best.sample.offset);
        let (max_error, estimated_error) = (best.distance(), best.sample.delay / 2);
        let corrected = clock::apply(correction, self.poll, max_error, estimated_error);
        let offset_ms = format!("{:+.3}", best.sample.offset as f64 / 1e6);
        let delay_ms = format!("{:.3}", best.sample.delay.as_secs_f64() * 1e3);
        let (server, address, stratum) = (&best.server, best.address, best.reply.stratum);
        if let Err(e) = corrected {
            tracing::error!(%server, %address, offset_ms, error = %e, "cannot correct the clock");
            return Err(format!("cannot correct the clock: {e}"));
        }
        if let Correction::Step(_) = correction {
            tracing::warn!(%server, %address, offset_ms, "clock stepped");
        }
        if self.corrected == Some(true) {
            tracing::debug!(%server, %address, stratum, offset_ms, delay_ms, "clock corrected");
        } else {
            tracing::info!(%server, %address, stratum, offset_ms, delay_ms, "clock synchronized");
        }
        self.poll = clock::next_poll(self.poll, correction);
        Ok(Measurement {
            source: Source::Ntp {
                server: best.server.clone(),
                address: best.address,
                stratum,
                reference: best.reply.reference_id(),
            },
            offset_ns: best.sample.offset,
            delay_ns: best
                .sample
                .delay
                .as_nanos()
                .try_into()
                .unwrap_or(Nanos::MAX),
            stepped: matches!(correction, Correction::Step(_)),
            at_unix_ns: now(),
        })
    }
}

#[must_use]
#[derive(Debug, thiserror::Error)]
enum Failure {
    #[error("no reply within {TIMEOUT:?}")]
    Timeout,
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Rejected(#[from] Rejected),
}

/// The addresses of `server`, on `port`.
async fn resolve(server: &TimeServer, port: u16) -> io::Result<Vec<SocketAddr>> {
    match server {
        TimeServer::Address(address) => Ok(vec![SocketAddr::new(*address, port)]),
        TimeServer::Host(host) => Ok(tokio::net::lookup_host((host.as_str(), port))
            .await?
            .collect()),
    }
}

/// Runs `futures` concurrently, and returns their outputs in their order: the order of preference
/// breaks ties.
async fn join_ordered<F>(futures: impl IntoIterator<Item = F>) -> Vec<F::Output>
where
    F: Future + Send + 'static,
    F::Output: Send,
{
    futures_util::future::join_all(futures).await
}

/// Sends a request to `address` and waits for its reply, for [`TIMEOUT`].
async fn query(address: SocketAddr) -> Result<(Reply, Sample), Failure> {
    tokio::time::timeout(TIMEOUT, exchange(address))
        .await
        .unwrap_or(Err(Failure::Timeout))
}

/// Sends a request to `address` and waits for its reply, ignoring datagrams that do not answer
/// it.
async fn exchange(address: SocketAddr) -> Result<(Reply, Sample), Failure> {
    let local: SocketAddr = match address {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let socket = UdpSocket::bind(local).await?;
    socket.connect(address).await?;
    let mut cookie = [0; 8];
    rustix::rand::getrandom(&mut cookie, GetRandomFlags::empty()).map_err(io::Error::from)?;

    let sent = now();
    socket.send(&packet::request(cookie)).await?;
    let mut buffer = [0; 1024];
    loop {
        // The task resumes when the reply is readable and receives it at once: the time is
        // taken right after.
        let length = socket.recv(&mut buffer).await?;
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Instant;

    use super::*;

    /// Answers every request on `socket` as a stratum 2 server whose clock is the local one.
    async fn serve(socket: UdpSocket) {
        let mut buffer = [0; 1024];
        loop {
            let (length, peer) = socket.recv_from(&mut buffer).await.unwrap();
            assert_eq!(length, 48);
            let mut reply = [0; 48];
            reply[0] = (4 << 3) | 4;
            reply[1] = 2;
            reply[24..32].copy_from_slice(&buffer[40..48]);
            let at = packet::tests::timestamp(now());
            reply[32..40].copy_from_slice(&at);
            reply[40..48].copy_from_slice(&at);
            socket.send_to(&reply, peer).await.unwrap();
        }
    }

    #[tokio::test]
    async fn queries_every_address_at_once() {
        let live = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = live.local_addr().unwrap().port();
        tokio::spawn(serve(live));
        // Bound, so the kernel does not refuse the queries, but silent.
        let dead: [IpAddr; 2] = ["127.0.0.2".parse().unwrap(), "127.0.0.3".parse().unwrap()];
        let mut silent = Vec::new();
        for address in dead {
            silent.push(UdpSocket::bind((address, port)).await.unwrap());
        }

        let servers = vec![
            TimeServer::Address(dead[0]),
            TimeServer::Address(dead[1]),
            "127.0.0.1".parse().unwrap(),
        ];
        let mut client = Client::new(NonEmpty::from_vec(servers).unwrap());
        client.port = port;
        let start = Instant::now();
        let best = client.best().await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(best.address, SocketAddr::from(([127, 0, 0, 1], port)));
        assert_eq!(best.reply.stratum, 2);
        assert!(best.sample.offset.abs() < 100_000_000, "{:?}", best.sample);
        // Queried in turn, the dead servers would take a timeout each.
        assert!(elapsed >= TIMEOUT, "{elapsed:?}");
        assert!(elapsed < TIMEOUT + Duration::from_secs(1), "{elapsed:?}");
    }
}

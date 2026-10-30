//! DHCPv4 client (RFC 2131).
//!
//! Packets are built and parsed by pure functions; the [`Client`] drives the state machine over
//! [`Transport`]s (in production a packet socket while acquiring a lease, see
//! [`crate::raw_socket`], and a UDP socket bound to the interface once it has an address) and
//! never touches the network configuration itself: it hands leases to its caller, which applies
//! them.

use std::fmt;
use std::future;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::str::FromStr;
use std::time::Duration;

use controllers_helpers::DomainName;
use controllers_helpers::Hostname;
use rustix::net::AddressFamily;
use rustix::net::SocketFlags;
use rustix::net::SocketType;
use rustix::net::sockopt;
use rustix::rand::GetRandomFlags;
use tokio::net::UdpSocket;
use tokio::time;
use tokio::time::Instant;

use crate::dhcp_message::DecodeError;
use crate::dhcp_message::Message;
use crate::dhcp_message::Opcode;
use crate::dhcp_option::DhcpOption;
use crate::dhcp_option::MessageType;
use crate::dhcp_option::OptionCode;
use crate::prefix_len::PrefixLen;

/// The port DHCP servers listen on.
pub const SERVER_PORT: u16 = 67;
/// The port DHCP clients listen on.
pub const CLIENT_PORT: u16 = 68;

/// Lease time meaning "never expires" (RFC 2131 §3.3).
const INFINITE: u32 = u32::MAX;

/// Options asked for in every request (option 55).
const REQUESTED_OPTIONS: [OptionCode; 12] = [
    OptionCode::SubnetMask,
    OptionCode::Router,
    OptionCode::DomainNameServer,
    OptionCode::Hostname,
    OptionCode::DomainName,
    OptionCode::InterfaceMtu,
    OptionCode::AddressLeaseTime,
    OptionCode::Renewal,
    OptionCode::Rebinding,
    OptionCode::DomainSearch,
    OptionCode::ClasslessStaticRoute,
    OptionCode::NtpServers,
];

/// Largest DHCP message we accept (option 57), an Ethernet frame minus the IP and UDP headers.
const MAX_MESSAGE_SIZE: u16 = 1500 - 20 - 8;

/// Some BOOTP relays and servers drop requests shorter than the original BOOTP message.
const MIN_PACKET_LEN: usize = 300;

/// Retransmissions of a REQUEST answering an OFFER before restarting discovery.
const REQUEST_ATTEMPTS: u32 = 4;

/// Shortest wait between retransmissions while renewing or rebinding (RFC 2131 §4.4.5).
const MIN_EXTEND_RETRANSMIT: Duration = Duration::from_secs(60);

/// A route learned from a lease. `gateway: None` is an on-link (link-scope) route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The network address of the destination.
    pub destination: Ipv4Addr,
    /// The prefix length of the destination.
    pub prefix_len: PrefixLen,
    /// The next hop, `None` on-link.
    pub gateway: Option<Ipv4Addr>,
}

impl Route {
    #[must_use]
    fn default_via(gateway: Ipv4Addr) -> Self {
        Self {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: PrefixLen::ZERO,
            gateway: Some(gateway),
        }
    }

    #[must_use]
    fn on_link_host(address: Ipv4Addr) -> Self {
        Self {
            destination: address,
            prefix_len: PrefixLen::HOST,
            gateway: None,
        }
    }
}

impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.destination, self.prefix_len)?;
        match self.gateway {
            Some(gateway) => write!(f, " via {gateway}"),
            None => f.write_str(" on-link"),
        }
    }
}

/// Lease timers, relative to [`Lease::start`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timers {
    /// T1: start renewing with the leasing server.
    pub renewal: Duration,
    /// T2: start rebinding with any server.
    pub rebinding: Duration,
    /// The end of the lease.
    pub expiry: Duration,
}

impl Timers {
    /// Timers for a lease of `lease` seconds; `None` for an infinite lease. T1 and T2 default to
    /// 0.5 and 0.875 of the lease (RFC 2131 §4.4.5) when missing or inconsistent.
    #[must_use]
    pub fn new(lease: u32, renewal: Option<u32>, rebinding: Option<u32>) -> Option<Self> {
        if lease == INFINITE {
            return None;
        }
        let secs = |s: u32| Duration::from_secs(s.into());
        let expiry = secs(lease);
        let rebinding = rebinding
            .map(secs)
            .filter(|&t2| t2 <= expiry)
            .unwrap_or(expiry * 7 / 8);
        let renewal = renewal
            .map(secs)
            .filter(|&t1| t1 <= rebinding)
            .unwrap_or_else(|| (expiry / 2).min(rebinding));
        Some(Self {
            renewal,
            rebinding,
            expiry,
        })
    }
}

/// A bound lease, as acknowledged by a server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The leased address.
    pub address: Ipv4Addr,
    /// The prefix length of the leased subnet (option 1).
    pub prefix_len: PrefixLen,
    /// The server that granted the lease, which renewals go to.
    pub server: Ipv4Addr,
    /// The first router (option 3), the most preferred: the default route's gateway.
    pub router: Option<Ipv4Addr>,
    /// Classless static routes (option 121); when present the router is ignored (RFC 3442).
    pub classless_routes: Vec<Route>,
    /// DNS servers (option 6), in order of preference.
    pub nameservers: Vec<Ipv4Addr>,
    /// NTP servers (option 42), in order of preference.
    pub ntp_servers: Vec<Ipv4Addr>,
    /// Option 15.
    pub domain_name: Option<DomainName>,
    /// Domain search list (option 119).
    pub search: Vec<DomainName>,
    /// Option 12.
    pub hostname: Option<Hostname>,
    /// Option 26, when at least 576.
    pub mtu: Option<u16>,
    /// `None` for an infinite lease.
    pub timers: Option<Timers>,
    /// When the request leading to this lease was sent; the timers count from there.
    pub start: Instant,
}

impl Lease {
    /// Lease time assumed when an ACK lacks option 51, which RFC 2131 requires.
    const DEFAULT_LEASE_TIME: u32 = 3600;

    fn from_ack(msg: &Message, source: Ipv4Addr, start: Instant) -> Result<Self, Rejected> {
        let address = offered_address(msg)?;
        let opts = &msg.options;
        let prefix_len = match opts.get(OptionCode::SubnetMask) {
            Some(DhcpOption::SubnetMask(mask)) => {
                PrefixLen::from_mask(*mask).ok_or(Rejected::BadSubnetMask(*mask))?
            }
            _ => PrefixLen::classful(address),
        };
        let addresses = |code| match opts.get(code) {
            Some(
                DhcpOption::Router(list)
                | DhcpOption::DomainNameServer(list)
                | DhcpOption::NtpServers(list),
            ) => list
                .iter()
                .copied()
                .filter(|a| !a.is_unspecified() && !a.is_broadcast())
                .collect(),
            _ => Vec::new(),
        };
        let u32_option = |code| match opts.get(code) {
            Some(
                DhcpOption::AddressLeaseTime(v) | DhcpOption::Renewal(v) | DhcpOption::Rebinding(v),
            ) => Some(*v),
            _ => None,
        };
        let classless_routes = match opts.get(OptionCode::ClasslessStaticRoute) {
            Some(DhcpOption::ClasslessStaticRoute(routes)) => routes.clone(),
            _ => Vec::new(),
        };
        let domain_name = match opts.get(OptionCode::DomainName) {
            Some(DhcpOption::DomainName(name)) => clean_name(name),
            _ => None,
        };
        let search = match opts.get(OptionCode::DomainSearch) {
            Some(DhcpOption::DomainSearch(names)) => names.clone(),
            _ => Vec::new(),
        };
        let hostname = match opts.get(OptionCode::Hostname) {
            Some(DhcpOption::Hostname(name)) => clean_name(name),
            _ => None,
        };
        let mtu = match opts.get(OptionCode::InterfaceMtu) {
            // RFC 2132 §5.1: the minimum legal value is 68; anything below 576 is a
            // misconfiguration that would break the link rather than help it.
            Some(DhcpOption::InterfaceMtu(mtu)) if *mtu >= 576 => Some(*mtu),
            _ => None,
        };

        Ok(Self {
            address,
            prefix_len,
            server: server_identifier(msg).unwrap_or(source),
            router: addresses(OptionCode::Router).first().copied(),
            classless_routes,
            nameservers: addresses(OptionCode::DomainNameServer),
            ntp_servers: addresses(OptionCode::NtpServers),
            domain_name,
            search,
            hostname,
            mtu,
            timers: Timers::new(
                u32_option(OptionCode::AddressLeaseTime).unwrap_or(Self::DEFAULT_LEASE_TIME),
                u32_option(OptionCode::Renewal),
                u32_option(OptionCode::Rebinding),
            ),
            start,
        })
    }

    /// Whether `address` is inside the leased subnet.
    #[must_use]
    fn contains(&self, address: Ipv4Addr) -> bool {
        let mask = self.prefix_len.mask();
        u32::from(address) & mask == u32::from(self.address) & mask
    }

    /// Routes to install, in order: classless static routes if any, else a default route through
    /// the router. A gateway outside the leased subnet (e.g. with /32 addresses) gets an
    /// on-link host route first, otherwise the kernel refuses routes through it.
    #[must_use]
    pub fn routes(&self) -> Vec<Route> {
        let gateway_routes = match self.router {
            Some(router) if self.classless_routes.is_empty() => vec![Route::default_via(router)],
            _ => self.classless_routes.clone(),
        };
        let mut routes = Vec::new();
        let mut push = |route: Route| {
            if !routes.contains(&route) {
                routes.push(route);
            }
        };
        for route in gateway_routes {
            if let Some(gateway) = route.gateway
                && !self.contains(gateway)
            {
                push(Route::on_link_host(gateway));
            }
            push(route);
        }
        routes
    }

    /// Remaining valid lifetime in seconds, as the kernel expects it (`u32::MAX` is forever).
    #[must_use]
    pub fn remaining_secs(&self, now: Instant) -> u32 {
        self.timers.map_or(INFINITE, |timers| {
            let left = (self.start + timers.expiry).saturating_duration_since(now);
            u32::try_from(left.as_secs()).unwrap_or(INFINITE - 1)
        })
    }
}

/// An OFFER worth requesting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Offer {
    /// The offered address.
    pub address: Ipv4Addr,
    /// The offering server, which the REQUEST selects.
    pub server: Ipv4Addr,
}

/// A DHCPNAK: the server refuses the requested address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nak {
    /// The refusing server, if it identified itself.
    pub server: Option<Ipv4Addr>,
    /// Its explanation (option 56), if any.
    pub message: Option<String>,
}

impl fmt::Display for Nak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DHCPNAK")?;
        if let Some(server) = self.server {
            write!(f, " from {server}")?;
        }
        write!(
            f,
            ": {}",
            self.message.as_deref().unwrap_or("no reason given")
        )
    }
}

/// A server's reply to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Offer(Offer),
    Ack(Box<Lease>),
    Nak(Nak),
}

impl Reply {
    #[must_use]
    fn server(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Offer(offer) => Some(offer.server),
            Self::Ack(lease) => Some(lease.server),
            Self::Nak(nak) => nak.server,
        }
    }
}

/// Why a received datagram was not taken into account.
#[must_use]
#[derive(Debug, thiserror::Error)]
pub enum Rejected {
    #[error("undecodable message: {0}")]
    Decode(#[from] DecodeError),
    #[error("not a BOOTREPLY")]
    NotReply,
    #[error("transaction ID mismatch")]
    Xid,
    #[error("hardware address mismatch")]
    HardwareAddress,
    #[error("unexpected message type {0:?}")]
    MessageType(Option<MessageType>),
    #[error("no usable address offered")]
    NoAddress,
    #[error("non-contiguous subnet mask {0}")]
    BadSubnetMask(Ipv4Addr),
}

/// Encodes `msg`, padded to the minimum BOOTP size.
#[must_use]
pub fn encode(msg: &Message) -> Vec<u8> {
    let mut buf = msg.encode();
    if buf.len() < MIN_PACKET_LEN {
        buf.resize(MIN_PACKET_LEN, 0);
    }
    buf
}

/// Decodes a datagram received from `source` and checks it answers transaction `xid` of the
/// client owning `mac`. `sent` is when the request was sent (the start of an acknowledged lease).
pub fn parse_reply(
    buf: &[u8],
    xid: u32,
    mac: &[u8; 6],
    source: Ipv4Addr,
    sent: Instant,
) -> Result<Reply, Rejected> {
    let msg = Message::decode(buf)?;
    if msg.opcode != Opcode::BootReply {
        return Err(Rejected::NotReply);
    }
    if msg.xid != xid {
        return Err(Rejected::Xid);
    }
    if msg.chaddr[..mac.len()] != *mac {
        return Err(Rejected::HardwareAddress);
    }
    match msg.options.message_type() {
        Some(MessageType::Offer) => Ok(Reply::Offer(Offer {
            address: offered_address(&msg)?,
            server: server_identifier(&msg).unwrap_or(source),
        })),
        Some(MessageType::Ack) => {
            Lease::from_ack(&msg, source, sent).map(|lease| Reply::Ack(Box::new(lease)))
        }
        Some(MessageType::Nak) => Ok(Reply::Nak(Nak {
            server: server_identifier(&msg),
            message: match msg.options.get(OptionCode::Message) {
                Some(DhcpOption::Message(text)) => Some(text.clone()),
                _ => None,
            },
        })),
        other => Err(Rejected::MessageType(other)),
    }
}

/// `yiaddr`, if it is an address a host can have.
fn offered_address(msg: &Message) -> Result<Ipv4Addr, Rejected> {
    let address = msg.yiaddr;
    if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
        return Err(Rejected::NoAddress);
    }
    Ok(address)
}

#[must_use]
fn server_identifier(msg: &Message) -> Option<Ipv4Addr> {
    match msg.options.get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(server)) if !server.is_unspecified() => Some(*server),
        _ => None,
    }
}

/// A domain or host name from an option, normalized; `None` if it is not a valid one.
#[must_use]
fn clean_name<T: FromStr>(name: &str) -> Option<T> {
    name.trim_end_matches('\0')
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .parse()
        .ok()
}

/// RFC 2131 §4.1 retransmission delay before the `attempt`-th retransmission: 4 s doubling up to
/// 64 s, randomized by ±1 s.
#[must_use]
pub fn retransmit_delay(attempt: u32, random: u32) -> Duration {
    let base = Duration::from_secs(4 << attempt.min(4));
    base - Duration::from_secs(1) + Duration::from_millis(u64::from(random % 2001))
}

/// A random number for transaction IDs and retransmission jitter, not for cryptography.
#[must_use]
pub fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    // GRND_INSECURE (Linux 5.6+) never blocks on an uninitialized pool, and requests of up to
    // 256 bytes are never short nor interrupted.
    rustix::rand::getrandom(&mut buf, GetRandomFlags::INSECURE)
        .expect("getrandom(GRND_INSECURE) does not fail");
    u32::from_ne_bytes(buf)
}

/// Datagram I/O used by the client.
pub trait Transport: Send + Sync {
    /// Sends the datagram `buf` to `target`.
    fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddrV4,
    ) -> impl Future<Output = io::Result<()>> + Send;

    /// Receives a datagram into `buf`: its length and source.
    fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;
}

impl Transport for UdpSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddrV4) -> io::Result<()> {
        UdpSocket::send_to(self, buf, target).await.map(drop)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf).await
    }
}

/// A UDP socket on `0.0.0.0:port`, bound to `ifname` so that each interface sees only its own
/// traffic and broadcasts leave through it, allowed to broadcast.
pub fn bind(ifname: &str, port: u16) -> io::Result<UdpSocket> {
    let fd = rustix::net::socket_with(
        AddressFamily::INET,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
        None,
    )?;
    // One socket per interface, all on port 68.
    sockopt::set_socket_reuseaddr(&fd, true)?;
    sockopt::set_socket_broadcast(&fd, true)?;
    let socket = UdpSocket::from_std(std::net::UdpSocket::from(fd))?;
    // Bound to the device before the port, so no other interface's datagram can sneak in.
    socket.bind_device(Some(ifname.as_bytes()))?;
    rustix::net::bind(&socket, &SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port))?;
    Ok(socket)
}

/// How a bound lease ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The lease was extended, maybe with new parameters.
    Renewed(Box<Lease>),
    Nak(Nak),
    Expired,
}

#[must_use]
#[derive(Debug, thiserror::Error)]
enum AcquireError {
    #[error("no answer to DHCPREQUEST")]
    RequestTimeout,
    #[error("{0}")]
    Nak(Nak),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// The DHCPv4 state machine of one interface.
pub struct Client {
    /// The interface's Ethernet address.
    mac: [u8; 6],
    /// The interface's name, for the logs.
    ifname: String,
}

impl Client {
    /// The client of the interface `ifname`, of Ethernet address `mac`.
    #[must_use]
    pub fn new(mac: [u8; 6], ifname: String) -> Self {
        Self { mac, ifname }
    }

    /// Option 61: hardware type (Ethernet) followed by the MAC address, as most clients send it.
    #[must_use]
    fn client_id(&self) -> Vec<u8> {
        let mut id = vec![1];
        id.extend_from_slice(&self.mac);
        id
    }

    /// A message of an interface without an address yet, which asks for broadcast replies: it
    /// cannot receive unicast ones.
    #[must_use]
    fn message(&self, xid: u32, secs: u16, kind: MessageType) -> Message {
        let mut msg = Message::new(Opcode::BootRequest, xid, self.mac);
        msg.secs = secs;
        msg.broadcast = true;
        let opts = &mut msg.options;
        opts.insert(DhcpOption::MessageType(kind));
        opts.insert(DhcpOption::ClientIdentifier(self.client_id()));
        opts.insert(DhcpOption::MaxMessageSize(MAX_MESSAGE_SIZE));
        opts.insert(DhcpOption::ParameterRequestList(
            REQUESTED_OPTIONS.map(|code| code as u8).to_vec(),
        ));
        msg
    }

    /// DISCOVER, broadcast.
    #[must_use]
    fn discover(&self, xid: u32, secs: u16) -> Message {
        self.message(xid, secs, MessageType::Discover)
    }

    /// REQUEST in the SELECTING state, answering `offer`.
    #[must_use]
    fn request_offer(&self, xid: u32, secs: u16, offer: &Offer) -> Message {
        let mut msg = self.message(xid, secs, MessageType::Request);
        msg.options
            .insert(DhcpOption::ServerIdentifier(offer.server));
        msg.options
            .insert(DhcpOption::RequestedIpAddress(offer.address));
        msg
    }

    /// REQUEST in the RENEWING or REBINDING state: `ciaddr` set, no server identifier nor
    /// requested address (RFC 2131 §4.3.2), and unicast replies to the leased address.
    #[must_use]
    fn request_extend(&self, xid: u32, secs: u16, lease: &Lease) -> Message {
        let mut msg = self.message(xid, secs, MessageType::Request);
        msg.broadcast = false;
        msg.ciaddr = lease.address;
        msg
    }

    /// INIT → SELECTING → REQUESTING → BOUND over `link` (a transport that works without an
    /// address). Retries until a lease is obtained.
    #[must_use]
    pub async fn acquire(&self, link: &impl Transport) -> Lease {
        loop {
            match self.try_acquire(link).await {
                Ok(lease) => return lease,
                Err(err) => {
                    let delay = Duration::from_secs(1)
                        + Duration::from_millis(u64::from(random_u32() % 4000));
                    tracing::warn!(
                        interface = %self.ifname,
                        "DHCP: {err}, restarting in {delay:.1?}"
                    );
                    time::sleep(delay).await;
                }
            }
        }
    }

    async fn try_acquire(&self, link: &impl Transport) -> Result<Lease, AcquireError> {
        let started = Instant::now();
        let secs = || u16::try_from(started.elapsed().as_secs()).unwrap_or(u16::MAX);
        let xid = random_u32();
        let broadcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT);

        let mut attempt = 0;
        let offer = loop {
            let msg = self.discover(xid, secs());
            let wait = retransmit_delay(attempt, random_u32());
            tracing::debug!(interface = %self.ifname, xid, "DHCPDISCOVER");
            let reply = self
                .transact(link, &msg, broadcast, wait, |r| {
                    matches!(r, Reply::Offer(_))
                })
                .await?;
            if let Some(Reply::Offer(offer)) = reply {
                break offer;
            }
            attempt = attempt.saturating_add(1);
        };
        tracing::debug!(
            interface = %self.ifname,
            address = %offer.address,
            server = %offer.server,
            "DHCPOFFER"
        );

        for attempt in 0..REQUEST_ATTEMPTS {
            let msg = self.request_offer(xid, secs(), &offer);
            let wait = retransmit_delay(attempt, random_u32());
            // Only the selected server answers; ignore stray replies from others.
            let from_selected = |r: &Reply| {
                matches!(r, Reply::Ack(_) | Reply::Nak(_))
                    && r.server().is_none_or(|s| s == offer.server)
            };
            match self
                .transact(link, &msg, broadcast, wait, from_selected)
                .await?
            {
                Some(Reply::Ack(lease)) => return Ok(*lease),
                Some(Reply::Nak(nak)) => return Err(AcquireError::Nak(nak)),
                _ => {}
            }
        }
        Err(AcquireError::RequestTimeout)
    }

    /// Waits for T1 then renews (RENEWING, unicast to the server), then rebinds after T2
    /// (REBINDING, broadcast), over `bound` (a transport using the leased address). Returns the
    /// renewed lease, or how it was lost.
    #[must_use]
    pub async fn maintain(&self, bound: &impl Transport, lease: &Lease) -> Outcome {
        let Some(timers) = lease.timers else {
            return future::pending().await;
        };
        time::sleep_until(lease.start + timers.renewal).await;
        tracing::debug!(
            interface = %self.ifname,
            "DHCP: renewing lease of {}",
            lease.address
        );
        let server = SocketAddrV4::new(lease.server, SERVER_PORT);
        if let Some(outcome) = self
            .extend(bound, lease, server, lease.start + timers.rebinding)
            .await
        {
            return outcome;
        }
        tracing::info!(
            interface = %self.ifname,
            "DHCP: rebinding lease of {}",
            lease.address
        );
        let broadcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT);
        let expiry = lease.start + timers.expiry;
        if let Some(outcome) = self.extend(bound, lease, broadcast, expiry).await {
            return outcome;
        }
        // Retransmissions are capped at the deadline, but replies are awaited up to it, not
        // past.
        time::sleep_until(expiry).await;
        Outcome::Expired
    }

    /// Sends extension REQUESTs to `target` until `deadline`, waiting half the remaining time
    /// (at least a minute) between retransmissions.
    async fn extend(
        &self,
        bound: &impl Transport,
        lease: &Lease,
        target: SocketAddrV4,
        deadline: Instant,
    ) -> Option<Outcome> {
        let started = Instant::now();
        let xid = random_u32();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let wait = (left / 2).max(MIN_EXTEND_RETRANSMIT).min(left);
            let secs = u16::try_from(started.elapsed().as_secs()).unwrap_or(u16::MAX);
            let msg = self.request_extend(xid, secs, lease);
            let ack_or_nak = |r: &Reply| matches!(r, Reply::Ack(_) | Reply::Nak(_));
            match self.transact(bound, &msg, target, wait, ack_or_nak).await {
                Ok(Some(Reply::Ack(lease))) => return Some(Outcome::Renewed(lease)),
                Ok(Some(Reply::Nak(nak))) => return Some(Outcome::Nak(nak)),
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(
                        interface = %self.ifname,
                        "DHCP: sending REQUEST to {target}: {err}"
                    );
                    time::sleep(wait).await;
                }
            }
        }
    }

    /// Sends `msg` to `target` then waits up to `wait` for a reply to it accepted by `wanted`.
    async fn transact(
        &self,
        transport: &impl Transport,
        msg: &Message,
        target: SocketAddrV4,
        wait: Duration,
        wanted: impl Fn(&Reply) -> bool,
    ) -> io::Result<Option<Reply>> {
        let packet = encode(msg);
        let sent = Instant::now();
        transport.send_to(&packet, target).await?;
        let deadline = sent + wait;
        let mut buf = vec![0u8; 1500];
        while let Ok(received) = time::timeout_at(deadline, transport.recv_from(&mut buf)).await {
            let (len, source) = received?;
            let source = match source.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => continue,
            };
            match parse_reply(&buf[..len], msg.xid, &self.mac, source, sent) {
                Ok(reply) if wanted(&reply) => return Ok(Some(reply)),
                Ok(reply) => {
                    tracing::debug!(interface = %self.ifname, "DHCP: ignoring {reply:?}");
                }
                Err(why) => tracing::trace!(
                    interface = %self.ifname,
                    "DHCP: ignoring datagram from {source}: {why}"
                ),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;
    use crate::dhcp_option::DhcpOptions;

    const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    fn client() -> Client {
        Client::new(MAC, "eth0".to_owned())
    }

    /// Builds a server reply to `request`, as a minimal DHCP server would.
    pub fn reply_to(
        request: &Message,
        kind: MessageType,
        address: Ipv4Addr,
        options: Vec<DhcpOption>,
    ) -> Vec<u8> {
        let mut msg = Message::new(Opcode::BootReply, request.xid, [0; 6]);
        msg.chaddr = request.chaddr;
        msg.ciaddr = request.ciaddr;
        msg.yiaddr = address;
        msg.options.insert(DhcpOption::MessageType(kind));
        msg.options.insert(DhcpOption::ServerIdentifier(SERVER));
        for opt in options {
            msg.options.insert(opt);
        }
        msg.encode()
    }

    fn basic_options() -> Vec<DhcpOption> {
        vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(10, 0, 0, 1)]),
            DhcpOption::DomainNameServer(vec![
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(10, 0, 0, 3),
            ]),
            DhcpOption::NtpServers(vec![Ipv4Addr::new(10, 0, 0, 4)]),
            DhcpOption::DomainName("Example.internal.".into()),
            DhcpOption::Hostname("web-1\0".into()),
            DhcpOption::InterfaceMtu(1460),
            DhcpOption::AddressLeaseTime(3600),
        ]
    }

    fn ack(options: Vec<DhcpOption>) -> Lease {
        let request = client().request_offer(
            7,
            0,
            &Offer {
                address: Ipv4Addr::new(10, 0, 0, 5),
                server: SERVER,
            },
        );
        let buf = reply_to(
            &request,
            MessageType::Ack,
            Ipv4Addr::new(10, 0, 0, 5),
            options,
        );
        match parse_reply(&buf, 7, &MAC, SERVER, Instant::now()).unwrap() {
            Reply::Ack(lease) => *lease,
            other => panic!("expected an ACK, got {other:?}"),
        }
    }

    fn decode(buf: &[u8]) -> Message {
        Message::decode(buf).unwrap()
    }

    /// The client's messages, byte for byte.
    #[test]
    fn encodes_the_wire_format() {
        /// Options 55, 57 and 61, then the end option.
        const COMMON_OPTIONS: &str = "370c0103060c0f1a333a3b77792a390205c03d0701020000000001ff";
        // A request in hexadecimal: `start` (from the opcode to the flags), `ciaddr`, the
        // hardware address, then the options before the common ones, padded.
        let wire = |start: &str, ciaddr: &str, options: &str| {
            let mut hex = format!(
                "{start}{ciaddr}{}020000000001{}63825363{options}{COMMON_OPTIONS}",
                "00".repeat(12),
                "00".repeat(10 + 192),
            );
            hex.push_str(&"00".repeat(MIN_PACKET_LEN - hex.len() / 2));
            hex
        };
        let offer = Offer {
            address: Ipv4Addr::new(10, 0, 0, 5),
            server: SERVER,
        };
        let lease = ack(basic_options());
        let cases = [
            (
                client().discover(0x1234_5678, 3),
                wire("010106001234567800038000", "00000000", "350101"),
            ),
            (
                client().request_offer(0x1234_5678, 4, &offer),
                wire(
                    "010106001234567800048000",
                    "00000000",
                    "32040a00000535010336040a000001",
                ),
            ),
            (
                client().request_extend(0x9abc_def0, 7, &lease),
                wire("010106009abcdef000070000", "0a000005", "350103"),
            ),
        ];
        for (msg, expected) in cases {
            let hex: String = encode(&msg).iter().map(|b| format!("{b:02x}")).collect();
            assert_eq!(hex, expected);
        }
    }

    #[test]
    fn discover_is_broadcast_and_requests_options() {
        let buf = encode(&client().discover(42, 3));
        assert!(buf.len() >= MIN_PACKET_LEN);
        let msg = decode(&buf);
        assert_eq!(msg.opcode, Opcode::BootRequest);
        assert_eq!(msg.xid, 42);
        assert_eq!(msg.secs, 3);
        assert!(msg.broadcast);
        assert_eq!(&msg.chaddr[..6], &MAC);
        assert_eq!(msg.options.message_type(), Some(MessageType::Discover));
        assert_eq!(
            msg.options.get(OptionCode::ClientIdentifier),
            Some(&DhcpOption::ClientIdentifier(vec![1, 2, 0, 0, 0, 0, 1]))
        );
        let Some(DhcpOption::ParameterRequestList(requested)) =
            msg.options.get(OptionCode::ParameterRequestList)
        else {
            panic!("no parameter request list");
        };
        for code in [
            OptionCode::ClasslessStaticRoute,
            OptionCode::InterfaceMtu,
            OptionCode::Router,
            OptionCode::NtpServers,
        ] {
            assert!(requested.contains(&(code as u8)), "{code:?} not requested");
        }
    }

    #[test]
    fn requests_carry_the_right_identifiers() {
        let offer = Offer {
            address: Ipv4Addr::new(10, 0, 0, 5),
            server: SERVER,
        };
        let msg = decode(&encode(&client().request_offer(9, 0, &offer)));
        assert_eq!(msg.options.message_type(), Some(MessageType::Request));
        assert!(msg.broadcast);
        assert_eq!(msg.ciaddr, Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            msg.options.get(OptionCode::ServerIdentifier),
            Some(&DhcpOption::ServerIdentifier(SERVER))
        );
        assert_eq!(
            msg.options.get(OptionCode::RequestedIpAddress),
            Some(&DhcpOption::RequestedIpAddress(offer.address))
        );

        let lease = ack(basic_options());
        let msg = decode(&encode(&client().request_extend(10, 0, &lease)));
        assert!(!msg.broadcast);
        assert_eq!(msg.ciaddr, lease.address);
        assert!(msg.options.get(OptionCode::ServerIdentifier).is_none());
        assert!(msg.options.get(OptionCode::RequestedIpAddress).is_none());
    }

    #[test]
    fn parses_offer() {
        let request = client().discover(1, 0);
        let buf = reply_to(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(10, 0, 0, 5),
            vec![],
        );
        let reply =
            parse_reply(&buf, 1, &MAC, Ipv4Addr::new(192, 0, 2, 1), Instant::now()).unwrap();
        assert_eq!(
            reply,
            Reply::Offer(Offer {
                address: Ipv4Addr::new(10, 0, 0, 5),
                server: SERVER
            })
        );
    }

    #[test]
    fn rejects_foreign_replies() {
        let request = client().discover(1, 0);
        let buf = reply_to(
            &request,
            MessageType::Offer,
            Ipv4Addr::new(10, 0, 0, 5),
            vec![],
        );
        let now = Instant::now();
        assert!(matches!(
            parse_reply(&buf, 2, &MAC, SERVER, now),
            Err(Rejected::Xid)
        ));
        assert!(matches!(
            parse_reply(&buf, 1, &[9; 6], SERVER, now),
            Err(Rejected::HardwareAddress)
        ));
        // Our own broadcast DISCOVER looping back.
        let own = encode(&request);
        assert!(matches!(
            parse_reply(&own, 1, &MAC, SERVER, now),
            Err(Rejected::NotReply)
        ));
        assert!(matches!(
            parse_reply(&[1, 2, 3], 1, &MAC, SERVER, now),
            Err(Rejected::Decode(_))
        ));
        let empty = reply_to(&request, MessageType::Offer, Ipv4Addr::UNSPECIFIED, vec![]);
        assert!(matches!(
            parse_reply(&empty, 1, &MAC, SERVER, now),
            Err(Rejected::NoAddress)
        ));
    }

    #[test]
    fn parses_ack() {
        let lease = ack(basic_options());
        assert_eq!(lease.address, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(lease.prefix_len.get(), 24);
        assert_eq!(lease.server, SERVER);
        assert_eq!(
            lease.nameservers,
            [Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)]
        );
        assert_eq!(lease.ntp_servers, [Ipv4Addr::new(10, 0, 0, 4)]);
        assert_eq!(
            lease.domain_name.as_ref().unwrap().as_str(),
            "example.internal"
        );
        assert_eq!(lease.hostname.as_ref().unwrap().as_str(), "web-1");
        assert_eq!(lease.mtu, Some(1460));
        assert_eq!(
            lease.routes(),
            [Route::default_via(Ipv4Addr::new(10, 0, 0, 1))]
        );
    }

    #[test]
    fn parses_nak() {
        let request = client().request_offer(
            5,
            0,
            &Offer {
                address: Ipv4Addr::new(10, 0, 0, 5),
                server: SERVER,
            },
        );
        let buf = reply_to(
            &request,
            MessageType::Nak,
            Ipv4Addr::UNSPECIFIED,
            vec![DhcpOption::Message("wrong network".into())],
        );
        let reply = parse_reply(&buf, 5, &MAC, SERVER, Instant::now()).unwrap();
        assert_eq!(
            reply,
            Reply::Nak(Nak {
                server: Some(SERVER),
                message: Some("wrong network".into())
            })
        );
    }

    #[test]
    fn subnet_mask_defaults_to_the_class() {
        let mut options = basic_options();
        options.retain(|o| !matches!(o, DhcpOption::SubnetMask(_)));
        assert_eq!(ack(options).prefix_len.get(), 8, "class A");
    }

    #[test]
    fn invalid_names_and_mtu_are_dropped() {
        let mut options = basic_options();
        options.push(DhcpOption::Hostname("not a hostname".into()));
        options.push(DhcpOption::InterfaceMtu(68));
        let lease = ack(options);
        assert_eq!(lease.hostname, None);
        assert_eq!(lease.mtu, None);
    }

    #[test]
    fn lease_timers_default_to_rfc_fractions() {
        let timers = Timers::new(1000, None, None).unwrap();
        assert_eq!(timers.renewal, Duration::from_secs(500));
        assert_eq!(timers.rebinding, Duration::from_secs(875));
        assert_eq!(timers.expiry, Duration::from_secs(1000));

        let explicit = Timers::new(1000, Some(300), Some(600)).unwrap();
        assert_eq!(
            (explicit.renewal, explicit.rebinding),
            (Duration::from_secs(300), Duration::from_secs(600))
        );

        // Inconsistent values fall back to the defaults.
        let bogus = Timers::new(1000, Some(900), Some(2000)).unwrap();
        assert_eq!(
            (bogus.renewal, bogus.rebinding),
            (Duration::from_secs(500), Duration::from_secs(875))
        );
        let short_t2 = Timers::new(1000, None, Some(400)).unwrap();
        assert_eq!(
            (short_t2.renewal, short_t2.rebinding),
            (Duration::from_secs(400), Duration::from_secs(400))
        );

        assert_eq!(Timers::new(INFINITE, None, None), None);

        let mut options = basic_options();
        options.push(DhcpOption::Renewal(1200));
        options.push(DhcpOption::Rebinding(3000));
        let lease = ack(options);
        let timers = lease.timers.unwrap();
        assert_eq!(timers.renewal, Duration::from_secs(1200));
        assert_eq!(timers.rebinding, Duration::from_secs(3000));
        assert_eq!(lease.remaining_secs(lease.start), 3600);
        assert_eq!(
            lease.remaining_secs(lease.start + Duration::from_secs(4000)),
            0
        );
    }

    /// Option 121 as raw bytes: 10.1.0.0/16 via 10.0.0.254, 0.0.0.0/0 via 10.0.0.1, and
    /// 169.254.169.254/32 on-link.
    fn classless_option() -> DhcpOption {
        let raw: &[u8] = &[
            16, 10, 1, 10, 0, 0, 254, //
            0, 10, 0, 0, 1, //
            32, 169, 254, 169, 254, 0, 0, 0, 0,
        ];
        let mut buf = vec![121, raw.len() as u8];
        buf.extend_from_slice(raw);
        buf.push(255);
        let opts = DhcpOptions::decode(&buf).unwrap();
        opts.get(OptionCode::ClasslessStaticRoute).unwrap().clone()
    }

    #[test]
    fn classless_routes_take_precedence_over_routers() {
        let mut options = basic_options();
        options.push(classless_option());
        let lease = ack(options);
        assert_eq!(lease.router, Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            lease.routes(),
            [
                Route {
                    destination: Ipv4Addr::new(10, 1, 0, 0),
                    prefix_len: PrefixLen::new(16).unwrap(),
                    gateway: Some(Ipv4Addr::new(10, 0, 0, 254))
                },
                Route::default_via(Ipv4Addr::new(10, 0, 0, 1)),
                Route::on_link_host(Ipv4Addr::new(169, 254, 169, 254)),
            ],
            "the router option must be ignored"
        );
    }

    #[test]
    fn off_subnet_gateway_gets_on_link_route() {
        // A /32 address and a gateway outside of it.
        let mut options = basic_options();
        options.retain(|o| !matches!(o, DhcpOption::SubnetMask(_) | DhcpOption::Router(_)));
        options.push(DhcpOption::SubnetMask(Ipv4Addr::BROADCAST));
        options.push(DhcpOption::Router(vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 9),
        ]));
        let lease = ack(options);
        let gateway = Ipv4Addr::new(10, 0, 0, 1);
        assert_eq!(
            lease.routes(),
            [Route::on_link_host(gateway), Route::default_via(gateway)]
        );

        // Already present in option 121: not duplicated, and kept before the routes using it.
        let mut options = basic_options();
        options.retain(|o| !matches!(o, DhcpOption::SubnetMask(_)));
        options.push(DhcpOption::SubnetMask(Ipv4Addr::BROADCAST));
        options.push(classless_option());
        let routes = ack(options).routes();
        assert_eq!(
            routes
                .iter()
                .filter(|r| **r == Route::on_link_host(gateway))
                .count(),
            1
        );
        let on_link = routes
            .iter()
            .position(|r| *r == Route::on_link_host(gateway))
            .unwrap();
        let default = routes
            .iter()
            .position(|r| *r == Route::default_via(gateway))
            .unwrap();
        assert!(on_link < default);
    }

    #[test]
    fn retransmission_backoff() {
        let bases: Vec<Duration> = (0..7)
            .map(|attempt| retransmit_delay(attempt, 1000))
            .collect();
        let secs = |s| Duration::from_secs(s);
        assert_eq!(
            bases,
            [
                secs(4),
                secs(8),
                secs(16),
                secs(32),
                secs(64),
                secs(64),
                secs(64)
            ]
        );
        assert_eq!(retransmit_delay(0, 0), secs(3));
        assert_eq!(retransmit_delay(0, 2000), secs(5));
    }

    /// Answers each sent message with the datagrams the script returns for it.
    type Script = Box<dyn Fn(&Message) -> Vec<Vec<u8>> + Send + Sync>;

    /// A message the client sent.
    struct Sent {
        message: Message,
        target: SocketAddrV4,
    }

    struct FakeServer {
        script: Script,
        inbox: Mutex<VecDeque<Vec<u8>>>,
        sent: Mutex<Vec<Sent>>,
    }

    impl FakeServer {
        fn new(script: impl Fn(&Message) -> Vec<Vec<u8>> + Send + Sync + 'static) -> Self {
            Self {
                script: Box::new(script),
                inbox: Mutex::default(),
                sent: Mutex::default(),
            }
        }
    }

    impl Transport for FakeServer {
        async fn send_to(&self, buf: &[u8], target: SocketAddrV4) -> io::Result<()> {
            let message = decode(buf);
            self.inbox.lock().unwrap().extend((self.script)(&message));
            self.sent.lock().unwrap().push(Sent { message, target });
            Ok(())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let next = self.inbox.lock().unwrap().pop_front();
            match next {
                Some(datagram) => {
                    buf[..datagram.len()].copy_from_slice(&datagram);
                    Ok((datagram.len(), SocketAddr::from((SERVER, SERVER_PORT))))
                }
                None => future::pending().await,
            }
        }
    }

    #[tokio::test]
    async fn acquires_lease_ignoring_noise() {
        let address = Ipv4Addr::new(10, 0, 0, 5);
        let server = FakeServer::new(move |msg| match msg.options.message_type() {
            Some(MessageType::Discover) => {
                let mut wrong_xid = msg.clone();
                wrong_xid.xid = msg.xid.wrapping_add(1);
                vec![
                    reply_to(
                        &wrong_xid,
                        MessageType::Offer,
                        Ipv4Addr::new(10, 0, 0, 66),
                        vec![],
                    ),
                    b"garbage".to_vec(),
                    reply_to(msg, MessageType::Offer, address, vec![]),
                ]
            }
            Some(MessageType::Request) => {
                vec![reply_to(msg, MessageType::Ack, address, basic_options())]
            }
            _ => vec![],
        });
        let lease = client().acquire(&server).await;
        assert_eq!(lease.address, address);

        let sent = server.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        let discover = &sent[0].message;
        assert_eq!(
            sent[0].target,
            SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT)
        );
        let request = &sent[1].message;
        assert_eq!(request.xid, discover.xid, "REQUEST reuses the OFFER's xid");
        assert_eq!(
            request.options.get(OptionCode::RequestedIpAddress),
            Some(&DhcpOption::RequestedIpAddress(address))
        );
    }

    #[tokio::test]
    async fn ignores_ack_from_unselected_server() {
        let address = Ipv4Addr::new(10, 0, 0, 5);
        let server = FakeServer::new(move |msg| match msg.options.message_type() {
            Some(MessageType::Discover) => vec![reply_to(msg, MessageType::Offer, address, vec![])],
            Some(MessageType::Request) => {
                let mut other = decode(&reply_to(msg, MessageType::Ack, address, vec![]));
                other
                    .options
                    .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 9, 9, 9)));
                vec![
                    other.encode(),
                    reply_to(msg, MessageType::Ack, address, basic_options()),
                ]
            }
            _ => vec![],
        });
        let lease = client().acquire(&server).await;
        assert_eq!(lease.server, SERVER);
    }

    #[tokio::test]
    async fn renewal_is_unicast_and_handles_nak() {
        let lease = Lease {
            timers: Timers::new(2, Some(0), Some(1)),
            ..ack(basic_options())
        };

        let server = FakeServer::new(|msg| {
            vec![reply_to(msg, MessageType::Ack, msg.ciaddr, basic_options())]
        });
        let Outcome::Renewed(renewed) = client().maintain(&server, &lease).await else {
            panic!("not renewed")
        };
        assert_eq!(renewed.address, lease.address);
        {
            let sent = server.sent.lock().unwrap();
            assert_eq!(sent[0].target, SocketAddrV4::new(SERVER, SERVER_PORT));
            assert_eq!(sent[0].message.ciaddr, lease.address);
        }

        let server = FakeServer::new(|msg| {
            vec![reply_to(
                msg,
                MessageType::Nak,
                Ipv4Addr::UNSPECIFIED,
                vec![],
            )]
        });
        assert!(matches!(
            client().maintain(&server, &lease).await,
            Outcome::Nak(_)
        ));
    }
}

//! DHCPv4 client (RFC 2131).
//!
//! Packets are built and parsed by pure functions; the [`Client`] drives the state machine over
//! [`Transport`]s (in production a packet socket while acquiring a lease, see [`super::raw`], and a
//! UDP socket bound to the interface once it has an address) and never touches the network
//! configuration itself: it hands leases to its caller, which applies them.

use std::fmt;
use std::future::{Future, pending};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Flags, Message, MessageType, Opcode, OptionCode};
use dhcproto::{Decodable, Encodable};
use rustix::net::{AddressFamily, SocketFlags, SocketType, sockopt};
use tokio::net::UdpSocket;
use tokio::time::{Instant, sleep, sleep_until, timeout_at};

use crate::types::Hostname;

pub const SERVER_PORT: u16 = 67;
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
    OptionCode::BroadcastAddr,
    OptionCode::AddressLeaseTime,
    OptionCode::Renewal,
    OptionCode::Rebinding,
    OptionCode::DomainSearch,
    OptionCode::ClasslessStaticRoute,
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
    pub destination: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Option<Ipv4Addr>,
}

impl Route {
    fn default_via(gateway: Ipv4Addr) -> Self {
        Self {
            destination: Ipv4Addr::UNSPECIFIED,
            prefix_len: 0,
            gateway: Some(gateway),
        }
    }

    fn on_link_host(address: Ipv4Addr) -> Self {
        Self {
            destination: address,
            prefix_len: 32,
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
    pub expiry: Duration,
}

impl Timers {
    /// Timers for a lease of `lease` seconds; `None` for an infinite lease. T1 and T2 default to
    /// 0.5 and 0.875 of the lease (RFC 2131 §4.4.5) when missing or inconsistent.
    pub fn new(lease: u32, renewal: Option<u32>, rebinding: Option<u32>) -> Option<Self> {
        if lease == INFINITE {
            return None;
        }
        let secs = |s: u32| Duration::from_secs(s.into());
        let expiry = secs(lease);
        let rebinding = rebinding.map(secs).filter(|&t2| t2 <= expiry).unwrap_or(expiry * 7 / 8);
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
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub server: Ipv4Addr,
    /// Routers (option 3), in order of preference.
    pub routers: Vec<Ipv4Addr>,
    /// Classless static routes (option 121); when present the routers are ignored (RFC 3442).
    pub classless_routes: Vec<Route>,
    pub nameservers: Vec<Ipv4Addr>,
    pub domain_name: Option<String>,
    /// Domain search list (option 119).
    pub search: Vec<String>,
    pub hostname: Option<Hostname>,
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
        let address = msg.yiaddr();
        if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
            return Err(Rejected::NoAddress);
        }
        let opts = msg.opts();
        let prefix_len = match opts.get(OptionCode::SubnetMask) {
            Some(DhcpOption::SubnetMask(mask)) => mask_to_prefix(*mask).ok_or(Rejected::BadSubnetMask(*mask))?,
            _ => classful_prefix(address),
        };
        let addresses = |code| match opts.get(code) {
            Some(DhcpOption::Router(list) | DhcpOption::DomainNameServer(list)) => list
                .iter()
                .copied()
                .filter(|a| !a.is_unspecified() && !a.is_broadcast())
                .collect(),
            _ => Vec::new(),
        };
        let u32_opt = |code| match opts.get(code) {
            Some(DhcpOption::AddressLeaseTime(v) | DhcpOption::Renewal(v) | DhcpOption::Rebinding(v)) => Some(*v),
            _ => None,
        };
        let classless_routes = match opts.get(OptionCode::ClasslessStaticRoute) {
            Some(DhcpOption::ClasslessStaticRoute(routes)) => routes
                .iter()
                .map(|(net, gateway)| Route {
                    destination: net.network(),
                    prefix_len: net.prefix_len(),
                    gateway: Some(*gateway).filter(|g| !g.is_unspecified()),
                })
                .collect(),
            _ => Vec::new(),
        };
        let domain_name = match opts.get(OptionCode::DomainName) {
            Some(DhcpOption::DomainName(name)) => clean_domain(name),
            _ => None,
        };
        let search = match opts.get(OptionCode::DomainSearch) {
            Some(DhcpOption::DomainSearch(names)) => {
                names.iter().filter_map(|name| clean_domain(&name.to_utf8())).collect()
            }
            _ => Vec::new(),
        };
        let hostname = match opts.get(OptionCode::Hostname) {
            Some(DhcpOption::Hostname(name)) => clean_domain(name).and_then(|name| name.parse().ok()),
            _ => None,
        };
        let mtu = match opts.get(OptionCode::InterfaceMtu) {
            // RFC 2132 §5.1: the minimum legal value is 68; anything below 576 is a misconfiguration
            // that would break the link rather than help it.
            Some(DhcpOption::InterfaceMtu(mtu)) if *mtu >= 576 => Some(*mtu),
            _ => None,
        };

        Ok(Self {
            address,
            prefix_len,
            server: server_identifier(msg).unwrap_or(source),
            routers: addresses(OptionCode::Router),
            classless_routes,
            nameservers: addresses(OptionCode::DomainNameServer),
            domain_name,
            search,
            hostname,
            mtu,
            timers: Timers::new(
                u32_opt(OptionCode::AddressLeaseTime).unwrap_or(Self::DEFAULT_LEASE_TIME),
                u32_opt(OptionCode::Renewal),
                u32_opt(OptionCode::Rebinding),
            ),
            start,
        })
    }

    /// Whether `address` is inside the leased subnet.
    pub fn contains(&self, address: Ipv4Addr) -> bool {
        let mask = prefix_to_mask(self.prefix_len);
        u32::from(address) & mask == u32::from(self.address) & mask
    }

    /// Routes to install, in order: classless static routes if any, else a default route through the
    /// first router. A gateway outside the leased subnet (e.g. with /32 addresses) gets an
    /// on-link host route first, otherwise the kernel refuses routes through it.
    pub fn routes(&self) -> Vec<Route> {
        let gateway_routes = if self.classless_routes.is_empty() {
            self.routers
                .first()
                .map(|&gw| Route::default_via(gw))
                .into_iter()
                .collect()
        } else {
            self.classless_routes.clone()
        };
        let mut routes = Vec::with_capacity(gateway_routes.len() * 2);
        let mut push = |route: Route| {
            if !routes.contains(&route) {
                routes.push(route);
            }
        };
        for route in gateway_routes {
            if let Some(gw) = route.gateway
                && !self.contains(gw)
            {
                push(Route::on_link_host(gw));
            }
            push(route);
        }
        routes
    }

    /// Remaining valid lifetime in seconds, as the kernel expects it (`u32::MAX` is forever).
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
    pub address: Ipv4Addr,
    pub server: Ipv4Addr,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nak {
    pub server: Option<Ipv4Addr>,
    pub message: Option<String>,
}

impl fmt::Display for Nak {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DHCPNAK")?;
        if let Some(server) = self.server {
            write!(f, " from {server}")?;
        }
        write!(f, ": {}", self.message.as_deref().unwrap_or("no reason given"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reply {
    Offer(Offer),
    Ack(Lease),
    Nak(Nak),
}

impl Reply {
    fn server(&self) -> Option<Ipv4Addr> {
        match self {
            Self::Offer(offer) => Some(offer.server),
            Self::Ack(lease) => Some(lease.server),
            Self::Nak(nak) => nak.server,
        }
    }
}

/// Why a received datagram was not taken into account.
#[derive(Debug, thiserror::Error)]
pub enum Rejected {
    #[error("undecodable message: {0}")]
    Decode(#[from] dhcproto::error::DecodeError),
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

/// Client-side identity, constant for an interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Identity {
    pub mac: [u8; 6],
}

impl Identity {
    /// Option 61: hardware type (Ethernet) followed by the MAC address, as most clients send it.
    fn client_id(&self) -> Vec<u8> {
        let mut id = Vec::with_capacity(7);
        id.push(1);
        id.extend_from_slice(&self.mac);
        id
    }

    fn message(&self, xid: u32, secs: u16, kind: MessageType, broadcast: bool) -> Message {
        let unspecified = Ipv4Addr::UNSPECIFIED;
        let mut msg = Message::new_with_id(xid, unspecified, unspecified, unspecified, unspecified, &self.mac);
        msg.set_secs(secs);
        if broadcast {
            // We cannot receive unicast before the address is configured.
            msg.set_flags(Flags::default().set_broadcast());
        }
        let opts = msg.opts_mut();
        opts.insert(DhcpOption::MessageType(kind));
        opts.insert(DhcpOption::ClientIdentifier(self.client_id()));
        opts.insert(DhcpOption::MaxMessageSize(MAX_MESSAGE_SIZE));
        opts.insert(DhcpOption::ParameterRequestList(REQUESTED_OPTIONS.to_vec()));
        msg
    }

    pub fn discover(&self, xid: u32, secs: u16) -> Message {
        self.message(xid, secs, MessageType::Discover, true)
    }

    /// REQUEST in the SELECTING state, answering `offer`.
    pub fn request_offer(&self, xid: u32, secs: u16, offer: &Offer) -> Message {
        let mut msg = self.message(xid, secs, MessageType::Request, true);
        msg.opts_mut().insert(DhcpOption::ServerIdentifier(offer.server));
        msg.opts_mut().insert(DhcpOption::RequestedIpAddress(offer.address));
        msg
    }

    /// REQUEST in the RENEWING or REBINDING state: `ciaddr` set, no server identifier nor
    /// requested address (RFC 2131 §4.3.2).
    pub fn request_extend(&self, xid: u32, secs: u16, lease: &Lease) -> Message {
        let mut msg = self.message(xid, secs, MessageType::Request, false);
        msg.set_ciaddr(lease.address);
        msg
    }
}

/// Encodes `msg`, padded to the minimum BOOTP size.
pub fn encode(msg: &Message) -> io::Result<Vec<u8>> {
    let mut buf = msg
        .to_vec()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    if buf.len() < MIN_PACKET_LEN {
        buf.resize(MIN_PACKET_LEN, 0);
    }
    Ok(buf)
}

/// Decodes a datagram received from `source` and checks it answers transaction `xid` of the
/// client owning `mac`. `sent` is when the request was sent (the start of an acknowledged lease).
pub fn parse_reply(buf: &[u8], xid: u32, mac: &[u8; 6], source: Ipv4Addr, sent: Instant) -> Result<Reply, Rejected> {
    let msg = Message::from_bytes(buf)?;
    if msg.opcode() != Opcode::BootReply {
        return Err(Rejected::NotReply);
    }
    if msg.xid() != xid {
        return Err(Rejected::Xid);
    }
    if msg.chaddr().get(..mac.len()) != Some(mac.as_slice()) {
        return Err(Rejected::HardwareAddress);
    }
    match msg.opts().msg_type() {
        Some(MessageType::Offer) => {
            let address = msg.yiaddr();
            if address.is_unspecified() || address.is_broadcast() || address.is_multicast() {
                return Err(Rejected::NoAddress);
            }
            Ok(Reply::Offer(Offer {
                address,
                server: server_identifier(&msg).unwrap_or(source),
            }))
        }
        Some(MessageType::Ack) => Lease::from_ack(&msg, source, sent).map(Reply::Ack),
        Some(MessageType::Nak) => Ok(Reply::Nak(Nak {
            server: server_identifier(&msg),
            message: match msg.opts().get(OptionCode::Message) {
                Some(DhcpOption::Message(text)) => Some(text.clone()),
                _ => None,
            },
        })),
        other => Err(Rejected::MessageType(other)),
    }
}

fn server_identifier(msg: &Message) -> Option<Ipv4Addr> {
    match msg.opts().get(OptionCode::ServerIdentifier) {
        Some(DhcpOption::ServerIdentifier(server)) if !server.is_unspecified() => Some(*server),
        _ => None,
    }
}

fn mask_to_prefix(mask: Ipv4Addr) -> Option<u8> {
    let bits = u32::from(mask);
    let ones = bits.leading_ones();
    (ones + bits.trailing_zeros() >= 32).then_some(ones as u8)
}

fn prefix_to_mask(prefix_len: u8) -> u32 {
    u32::MAX.checked_shl(32 - u32::from(prefix_len.min(32))).unwrap_or(0)
}

/// Prefix length implied by the address class, for servers omitting the subnet mask.
fn classful_prefix(address: Ipv4Addr) -> u8 {
    match address.octets()[0] {
        0..128 => 8,
        128..192 => 16,
        _ => 24,
    }
}

/// Normalizes a domain or host name from an option; `None` if it is not a valid name.
fn clean_domain(name: &str) -> Option<String> {
    let name = name.trim_end_matches('\0').trim_end_matches('.').to_ascii_lowercase();
    // Domain names follow the hostname syntax.
    name.parse::<Hostname>().ok().map(String::from)
}

/// RFC 2131 §4.1 retransmission delay before the `attempt`-th retransmission: 4 s doubling up to
/// 64 s, randomized by ±1 s.
pub fn retransmit_delay(attempt: u32, random: u32) -> Duration {
    let base = Duration::from_secs(4 << attempt.min(4));
    base - Duration::from_secs(1) + Duration::from_millis(u64::from(random % 2001))
}

pub fn random_u32() -> u32 {
    let mut buf = [0u8; 4];
    // GRND_INSECURE never blocks on an uninitialized pool (Linux 5.6+); none of our uses is
    // cryptographic. Older kernels reject the flag.
    let filled = rustix::rand::getrandom(&mut buf, rustix::rand::GetRandomFlags::INSECURE)
        .or_else(|_| rustix::rand::getrandom(&mut buf, rustix::rand::GetRandomFlags::empty()));
    if filled.is_ok_and(|n| n == buf.len()) {
        u32::from_ne_bytes(buf)
    } else {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos())
    }
}

/// Datagram I/O used by the client.
pub trait Transport: Send + Sync {
    fn send_to(&self, buf: &[u8], target: SocketAddrV4) -> impl Future<Output = io::Result<()>> + Send;
    fn recv_from(&self, buf: &mut [u8]) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;
}

impl Transport for UdpSocket {
    async fn send_to(&self, buf: &[u8], target: SocketAddrV4) -> io::Result<()> {
        UdpSocket::send_to(self, buf, target).await.map(drop)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        UdpSocket::recv_from(self, buf).await
    }
}

/// Opens the client socket of `ifname`: bound to `0.0.0.0:68` and to the device, so that each
/// interface sees only its own traffic and broadcasts leave through it.
pub fn bind(ifname: &str) -> io::Result<UdpSocket> {
    bind_port(ifname, CLIENT_PORT)
}

/// A UDP socket on `0.0.0.0:port`, bound to `ifname`, allowed to broadcast.
pub fn bind_port(ifname: &str, port: u16) -> io::Result<UdpSocket> {
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
    Renewed(Lease),
    Nak(Nak),
    Expired,
}

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
pub struct Client<T> {
    transport: T,
    identity: Identity,
    ifname: String,
}

impl<T: Transport> Client<T> {
    pub fn new(transport: T, identity: Identity, ifname: impl Into<String>) -> Self {
        Self {
            transport,
            identity,
            ifname: ifname.into(),
        }
    }

    /// INIT → SELECTING → REQUESTING → BOUND over `link` (a transport that works without an
    /// address). Retries until a lease is obtained.
    pub async fn acquire(&self, link: &impl Transport) -> Lease {
        loop {
            match self.try_acquire(link).await {
                Ok(lease) => return lease,
                Err(err) => {
                    let delay = Duration::from_secs(1) + Duration::from_millis(u64::from(random_u32() % 4000));
                    tracing::warn!(interface = %self.ifname, "DHCP: {err}, restarting in {delay:.1?}");
                    sleep(delay).await;
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
            let msg = self.identity.discover(xid, secs());
            let wait = retransmit_delay(attempt, random_u32());
            tracing::debug!(interface = %self.ifname, xid, "DHCPDISCOVER");
            let reply = self
                .transact(link, &msg, broadcast, wait, |r| matches!(r, Reply::Offer(_)))
                .await?;
            if let Some(Reply::Offer(offer)) = reply {
                break offer;
            }
            attempt = attempt.saturating_add(1);
        };
        tracing::debug!(interface = %self.ifname, address = %offer.address, server = %offer.server, "DHCPOFFER");

        for attempt in 0..REQUEST_ATTEMPTS {
            let msg = self.identity.request_offer(xid, secs(), &offer);
            let wait = retransmit_delay(attempt, random_u32());
            // Only the selected server answers; ignore stray replies from others.
            let from_selected =
                |r: &Reply| matches!(r, Reply::Ack(_) | Reply::Nak(_)) && r.server().is_none_or(|s| s == offer.server);
            match self.transact(link, &msg, broadcast, wait, from_selected).await? {
                Some(Reply::Ack(lease)) => return Ok(lease),
                Some(Reply::Nak(nak)) => return Err(AcquireError::Nak(nak)),
                _ => {}
            }
        }
        Err(AcquireError::RequestTimeout)
    }

    /// Waits for T1 then renews (RENEWING, unicast to the server), then rebinds after T2
    /// (REBINDING, broadcast). Returns the renewed lease, or how it was lost.
    pub async fn maintain(&self, lease: &Lease) -> Outcome {
        let Some(timers) = lease.timers else {
            return pending().await;
        };
        sleep_until(lease.start + timers.renewal).await;
        tracing::debug!(interface = %self.ifname, "DHCP: renewing lease of {}", lease.address);
        let server = SocketAddrV4::new(lease.server, SERVER_PORT);
        if let Some(outcome) = self.extend(lease, server, lease.start + timers.rebinding).await {
            return outcome;
        }
        tracing::info!(interface = %self.ifname, "DHCP: rebinding lease of {}", lease.address);
        let broadcast = SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT);
        let expiry = lease.start + timers.expiry;
        if let Some(outcome) = self.extend(lease, broadcast, expiry).await {
            return outcome;
        }
        // Retransmissions are capped at the deadline, but replies are awaited up to it, not past.
        sleep_until(expiry).await;
        Outcome::Expired
    }

    /// Sends extension REQUESTs to `target` until `deadline`, waiting half the remaining time
    /// (at least a minute) between retransmissions.
    async fn extend(&self, lease: &Lease, target: SocketAddrV4, deadline: Instant) -> Option<Outcome> {
        let started = Instant::now();
        let xid = random_u32();
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let wait = (left / 2).max(MIN_EXTEND_RETRANSMIT).min(left);
            let secs = u16::try_from(started.elapsed().as_secs()).unwrap_or(u16::MAX);
            let msg = self.identity.request_extend(xid, secs, lease);
            let ack_or_nak = |r: &Reply| matches!(r, Reply::Ack(_) | Reply::Nak(_));
            match self.transact(&self.transport, &msg, target, wait, ack_or_nak).await {
                Ok(Some(Reply::Ack(lease))) => return Some(Outcome::Renewed(lease)),
                Ok(Some(Reply::Nak(nak))) => return Some(Outcome::Nak(nak)),
                Ok(_) => {}
                Err(err) => {
                    tracing::warn!(interface = %self.ifname, "DHCP: sending REQUEST to {target}: {err}");
                    sleep_until(Instant::now() + wait).await;
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
        let packet = encode(msg)?;
        let sent = Instant::now();
        transport.send_to(&packet, target).await?;
        let deadline = sent + wait;
        let mut buf = vec![0u8; 1500];
        while let Ok(received) = timeout_at(deadline, transport.recv_from(&mut buf)).await {
            let (len, source) = received?;
            let source = match source.ip() {
                IpAddr::V4(ip) => ip,
                IpAddr::V6(_) => continue,
            };
            match parse_reply(&buf[..len], msg.xid(), &self.identity.mac, source, sent) {
                Ok(reply) if wanted(&reply) => return Ok(Some(reply)),
                Ok(reply) => tracing::debug!(interface = %self.ifname, "DHCP: ignoring {reply:?}"),
                Err(why) => tracing::trace!(interface = %self.ifname, "DHCP: ignoring datagram from {source}: {why}"),
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    pub const MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    pub const SERVER: Ipv4Addr = Ipv4Addr::new(10, 0, 0, 1);

    pub fn identity() -> Identity {
        Identity { mac: MAC }
    }

    /// Builds a server reply to `request`, as a minimal DHCP server would.
    pub fn reply_to(request: &Message, kind: MessageType, address: Ipv4Addr, options: Vec<DhcpOption>) -> Vec<u8> {
        let mut msg = Message::new_with_id(
            request.xid(),
            request.ciaddr(),
            address,
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::UNSPECIFIED,
            request.chaddr(),
        );
        msg.set_opcode(Opcode::BootReply);
        msg.opts_mut().insert(DhcpOption::MessageType(kind));
        msg.opts_mut().insert(DhcpOption::ServerIdentifier(SERVER));
        for opt in options {
            msg.opts_mut().insert(opt);
        }
        msg.to_vec().unwrap()
    }

    fn basic_options() -> Vec<DhcpOption> {
        vec![
            DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)),
            DhcpOption::Router(vec![Ipv4Addr::new(10, 0, 0, 1)]),
            DhcpOption::DomainNameServer(vec![Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)]),
            DhcpOption::DomainName("Example.internal.".into()),
            DhcpOption::Hostname("web-1\0".into()),
            DhcpOption::InterfaceMtu(1460),
            DhcpOption::AddressLeaseTime(3600),
        ]
    }

    fn ack(options: Vec<DhcpOption>) -> Lease {
        let request = identity().request_offer(
            7,
            0,
            &Offer {
                address: Ipv4Addr::new(10, 0, 0, 5),
                server: SERVER,
            },
        );
        let buf = reply_to(&request, MessageType::Ack, Ipv4Addr::new(10, 0, 0, 5), options);
        match parse_reply(&buf, 7, &MAC, SERVER, Instant::now()).unwrap() {
            Reply::Ack(lease) => lease,
            other => panic!("expected an ACK, got {other:?}"),
        }
    }

    fn decode(buf: &[u8]) -> Message {
        Message::from_bytes(buf).unwrap()
    }

    #[test]
    fn discover_is_broadcast_and_requests_options() {
        let buf = encode(&identity().discover(42, 3)).unwrap();
        assert!(buf.len() >= MIN_PACKET_LEN);
        let msg = decode(&buf);
        assert_eq!(msg.opcode(), Opcode::BootRequest);
        assert_eq!(msg.xid(), 42);
        assert_eq!(msg.secs(), 3);
        assert!(msg.flags().broadcast());
        assert_eq!(&msg.chaddr()[..6], &MAC);
        assert_eq!(msg.opts().msg_type(), Some(MessageType::Discover));
        assert_eq!(
            msg.opts().get(OptionCode::ClientIdentifier),
            Some(&DhcpOption::ClientIdentifier(vec![1, 2, 0, 0, 0, 0, 1]))
        );
        let Some(DhcpOption::ParameterRequestList(prl)) = msg.opts().get(OptionCode::ParameterRequestList) else {
            panic!("no parameter request list");
        };
        for code in [
            OptionCode::ClasslessStaticRoute,
            OptionCode::InterfaceMtu,
            OptionCode::Router,
        ] {
            assert!(prl.contains(&code), "{code:?} not requested");
        }
    }

    #[test]
    fn requests_carry_the_right_identifiers() {
        let offer = Offer {
            address: Ipv4Addr::new(10, 0, 0, 5),
            server: SERVER,
        };
        let msg = decode(&encode(&identity().request_offer(9, 0, &offer)).unwrap());
        assert_eq!(msg.opts().msg_type(), Some(MessageType::Request));
        assert!(msg.flags().broadcast());
        assert_eq!(msg.ciaddr(), Ipv4Addr::UNSPECIFIED);
        assert_eq!(
            msg.opts().get(OptionCode::ServerIdentifier),
            Some(&DhcpOption::ServerIdentifier(SERVER))
        );
        assert_eq!(
            msg.opts().get(OptionCode::RequestedIpAddress),
            Some(&DhcpOption::RequestedIpAddress(offer.address))
        );

        let lease = ack(basic_options());
        let msg = decode(&encode(&identity().request_extend(10, 0, &lease)).unwrap());
        assert!(!msg.flags().broadcast());
        assert_eq!(msg.ciaddr(), lease.address);
        assert!(msg.opts().get(OptionCode::ServerIdentifier).is_none());
        assert!(msg.opts().get(OptionCode::RequestedIpAddress).is_none());
    }

    #[test]
    fn parses_offer() {
        let request = identity().discover(1, 0);
        let buf = reply_to(&request, MessageType::Offer, Ipv4Addr::new(10, 0, 0, 5), vec![]);
        let reply = parse_reply(&buf, 1, &MAC, Ipv4Addr::new(192, 0, 2, 1), Instant::now()).unwrap();
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
        let request = identity().discover(1, 0);
        let buf = reply_to(&request, MessageType::Offer, Ipv4Addr::new(10, 0, 0, 5), vec![]);
        let now = Instant::now();
        assert!(matches!(parse_reply(&buf, 2, &MAC, SERVER, now), Err(Rejected::Xid)));
        assert!(matches!(
            parse_reply(&buf, 1, &[9; 6], SERVER, now),
            Err(Rejected::HardwareAddress)
        ));
        // Our own broadcast DISCOVER looping back.
        let own = encode(&request).unwrap();
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
        assert_eq!(lease.prefix_len, 24);
        assert_eq!(lease.server, SERVER);
        assert_eq!(
            lease.nameservers,
            [Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(10, 0, 0, 3)]
        );
        assert_eq!(lease.domain_name.as_deref(), Some("example.internal"));
        assert_eq!(lease.hostname.as_ref().map(Hostname::as_str), Some("web-1"));
        assert_eq!(lease.mtu, Some(1460));
        assert_eq!(lease.routes(), [Route::default_via(Ipv4Addr::new(10, 0, 0, 1))]);
    }

    #[test]
    fn parses_nak() {
        let request = identity().request_offer(
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
    fn subnet_mask_handling() {
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 255, 255)), Some(32));
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 255, 240, 0)), Some(20));
        assert_eq!(mask_to_prefix(Ipv4Addr::UNSPECIFIED), Some(0));
        assert_eq!(mask_to_prefix(Ipv4Addr::new(255, 0, 255, 0)), None);
        assert_eq!(prefix_to_mask(0), 0);
        assert_eq!(prefix_to_mask(32), u32::MAX);

        let mut options = basic_options();
        options.retain(|o| !matches!(o, DhcpOption::SubnetMask(_)));
        assert_eq!(ack(options).prefix_len, 8, "class A default");
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
        assert!(lease.remaining_secs(lease.start) == 3600);
        assert_eq!(lease.remaining_secs(lease.start + Duration::from_secs(4000)), 0);
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
        let opts = dhcproto::v4::DhcpOptions::decode(&mut dhcproto::Decoder::new(&buf)).unwrap();
        opts.get(OptionCode::ClasslessStaticRoute).unwrap().clone()
    }

    #[test]
    fn classless_routes_take_precedence_over_routers() {
        let mut options = basic_options();
        options.push(classless_option());
        let lease = ack(options);
        assert_eq!(lease.routers, [Ipv4Addr::new(10, 0, 0, 1)]);
        assert_eq!(
            lease.routes(),
            [
                Route {
                    destination: Ipv4Addr::new(10, 1, 0, 0),
                    prefix_len: 16,
                    gateway: Some(Ipv4Addr::new(10, 0, 0, 254))
                },
                Route::default_via(Ipv4Addr::new(10, 0, 0, 1)),
                Route {
                    destination: Ipv4Addr::new(169, 254, 169, 254),
                    prefix_len: 32,
                    gateway: None
                },
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
        assert_eq!(routes.iter().filter(|r| **r == Route::on_link_host(gateway)).count(), 1);
        let on_link = routes.iter().position(|r| *r == Route::on_link_host(gateway)).unwrap();
        let default = routes.iter().position(|r| *r == Route::default_via(gateway)).unwrap();
        assert!(on_link < default);
    }

    #[test]
    fn retransmission_backoff() {
        let bases: Vec<_> = (0..7).map(|attempt| retransmit_delay(attempt, 1000)).collect();
        let secs = |s| Duration::from_secs(s);
        assert_eq!(
            bases,
            [secs(4), secs(8), secs(16), secs(32), secs(64), secs(64), secs(64)]
        );
        assert_eq!(retransmit_delay(0, 0), secs(3));
        assert_eq!(retransmit_delay(0, 2000), secs(5));
    }

    /// Answers each sent message with the datagrams the script returns for it.
    type Script = Box<dyn Fn(&Message) -> Vec<Vec<u8>> + Send + Sync>;

    pub struct FakeServer {
        script: Script,
        inbox: Mutex<VecDeque<Vec<u8>>>,
        pub sent: Mutex<Vec<(Message, SocketAddrV4)>>,
    }

    impl FakeServer {
        pub fn new(script: impl Fn(&Message) -> Vec<Vec<u8>> + Send + Sync + 'static) -> Self {
            Self {
                script: Box::new(script),
                inbox: Mutex::default(),
                sent: Mutex::default(),
            }
        }
    }

    impl Transport for FakeServer {
        async fn send_to(&self, buf: &[u8], target: SocketAddrV4) -> io::Result<()> {
            let msg = decode(buf);
            self.inbox.lock().unwrap().extend((self.script)(&msg));
            self.sent.lock().unwrap().push((msg, target));
            Ok(())
        }

        async fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
            let next = self.inbox.lock().unwrap().pop_front();
            match next {
                Some(datagram) => {
                    buf[..datagram.len()].copy_from_slice(&datagram);
                    Ok((datagram.len(), SocketAddr::from((SERVER, SERVER_PORT))))
                }
                None => pending().await,
            }
        }
    }

    #[tokio::test]
    async fn acquires_lease_ignoring_noise() {
        let address = Ipv4Addr::new(10, 0, 0, 5);
        let server = FakeServer::new(move |msg| match msg.opts().msg_type() {
            Some(MessageType::Discover) => {
                let mut wrong_xid = msg.clone();
                wrong_xid.set_xid(msg.xid().wrapping_add(1));
                vec![
                    reply_to(&wrong_xid, MessageType::Offer, Ipv4Addr::new(10, 0, 0, 66), vec![]),
                    b"garbage".to_vec(),
                    reply_to(msg, MessageType::Offer, address, vec![]),
                ]
            }
            Some(MessageType::Request) => vec![reply_to(msg, MessageType::Ack, address, basic_options())],
            _ => vec![],
        });
        let client = Client::new(server, identity(), "eth0");
        let lease = client.acquire(&client.transport).await;
        assert_eq!(lease.address, address);

        let sent = client.transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        let (discover, target) = &sent[0];
        assert_eq!(*target, SocketAddrV4::new(Ipv4Addr::BROADCAST, SERVER_PORT));
        let (request, _) = &sent[1];
        assert_eq!(request.xid(), discover.xid(), "REQUEST reuses the OFFER's xid");
        assert_eq!(
            request.opts().get(OptionCode::RequestedIpAddress),
            Some(&DhcpOption::RequestedIpAddress(address))
        );
    }

    #[tokio::test]
    async fn ignores_ack_from_unselected_server() {
        let address = Ipv4Addr::new(10, 0, 0, 5);
        let server = FakeServer::new(move |msg| match msg.opts().msg_type() {
            Some(MessageType::Discover) => vec![reply_to(msg, MessageType::Offer, address, vec![])],
            Some(MessageType::Request) => {
                let mut other = Message::from_bytes(&reply_to(msg, MessageType::Ack, address, vec![])).unwrap();
                other
                    .opts_mut()
                    .insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(10, 9, 9, 9)));
                vec![
                    other.to_vec().unwrap(),
                    reply_to(msg, MessageType::Ack, address, basic_options()),
                ]
            }
            _ => vec![],
        });
        let client = Client::new(server, identity(), "eth0");
        let lease = client.acquire(&client.transport).await;
        assert_eq!(lease.server, SERVER);
    }

    #[tokio::test]
    async fn renewal_is_unicast_and_handles_nak() {
        let lease = Lease {
            timers: Timers::new(2, Some(0), Some(1)),
            ..ack(basic_options())
        };

        let server = FakeServer::new(|msg| vec![reply_to(msg, MessageType::Ack, msg.ciaddr(), basic_options())]);
        let client = Client::new(server, identity(), "eth0");
        let Outcome::Renewed(renewed) = client.maintain(&lease).await else {
            panic!("not renewed")
        };
        assert_eq!(renewed.address, lease.address);
        {
            let sent = client.transport.sent.lock().unwrap();
            assert_eq!(sent[0].1, SocketAddrV4::new(SERVER, SERVER_PORT));
            assert_eq!(sent[0].0.ciaddr(), lease.address);
        }

        let server = FakeServer::new(|msg| vec![reply_to(msg, MessageType::Nak, Ipv4Addr::UNSPECIFIED, vec![])]);
        let client = Client::new(server, identity(), "eth0");
        assert!(matches!(client.maintain(&lease).await, Outcome::Nak(_)));
    }
}

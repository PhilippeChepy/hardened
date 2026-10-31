//! DHCPv4 options (RFC 2132 and extensions): those network-controller sends or reads. Options are
//! decoded defensively: a malformed one is dropped, and only a TLV running past the end of the
//! message rejects it.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use controllers_helpers::DomainName;

use crate::dhcp::Route;
use crate::dhcp_message::DecodeError;
use crate::domain_search;
use crate::prefix_len::PrefixLen;

/// Padding between options.
const PAD: u8 = 0;
/// The end of the options.
const END: u8 = 255;
/// The longest value of a single option; longer ones span several (RFC 3396).
const MAX_VALUE_LEN: usize = 255;

/// The codes of the options handled, declared in numeric order: options are encoded in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum OptionCode {
    SubnetMask = 1,
    Router = 3,
    DomainNameServer = 6,
    Hostname = 12,
    DomainName = 15,
    InterfaceMtu = 26,
    NtpServers = 42,
    RequestedIpAddress = 50,
    AddressLeaseTime = 51,
    MessageType = 53,
    ServerIdentifier = 54,
    ParameterRequestList = 55,
    Message = 56,
    MaxMessageSize = 57,
    Renewal = 58,
    Rebinding = 59,
    ClientIdentifier = 61,
    DomainSearch = 119,
    ClasslessStaticRoute = 121,
}

impl OptionCode {
    const ALL: [Self; 19] = [
        Self::SubnetMask,
        Self::Router,
        Self::DomainNameServer,
        Self::Hostname,
        Self::DomainName,
        Self::InterfaceMtu,
        Self::NtpServers,
        Self::RequestedIpAddress,
        Self::AddressLeaseTime,
        Self::MessageType,
        Self::ServerIdentifier,
        Self::ParameterRequestList,
        Self::Message,
        Self::MaxMessageSize,
        Self::Renewal,
        Self::Rebinding,
        Self::ClientIdentifier,
        Self::DomainSearch,
        Self::ClasslessStaticRoute,
    ];

    /// The option of code `code`, if handled.
    #[must_use]
    fn from_u8(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|known| *known as u8 == code)
    }
}

/// DHCP message types (option 53): those the client sends and receives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Ack = 5,
    Nak = 6,
}

impl MessageType {
    #[must_use]
    fn from_u8(value: u8) -> Option<Self> {
        [
            Self::Discover,
            Self::Offer,
            Self::Request,
            Self::Ack,
            Self::Nak,
        ]
        .into_iter()
        .find(|kind| *kind as u8 == value)
    }
}

/// An option and its value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DhcpOption {
    SubnetMask(Ipv4Addr),
    Router(Vec<Ipv4Addr>),
    DomainNameServer(Vec<Ipv4Addr>),
    Hostname(String),
    DomainName(String),
    InterfaceMtu(u16),
    NtpServers(Vec<Ipv4Addr>),
    RequestedIpAddress(Ipv4Addr),
    AddressLeaseTime(u32),
    MessageType(MessageType),
    ServerIdentifier(Ipv4Addr),
    /// Option codes.
    ParameterRequestList(Vec<u8>),
    Message(String),
    MaxMessageSize(u16),
    Renewal(u32),
    Rebinding(u32),
    ClientIdentifier(Vec<u8>),
    /// The valid names of the list, lowercase.
    DomainSearch(Vec<DomainName>),
    ClasslessStaticRoute(Vec<Route>),
}

impl DhcpOption {
    /// Its code.
    #[must_use]
    pub fn code(&self) -> OptionCode {
        match self {
            Self::SubnetMask(_) => OptionCode::SubnetMask,
            Self::Router(_) => OptionCode::Router,
            Self::DomainNameServer(_) => OptionCode::DomainNameServer,
            Self::Hostname(_) => OptionCode::Hostname,
            Self::DomainName(_) => OptionCode::DomainName,
            Self::InterfaceMtu(_) => OptionCode::InterfaceMtu,
            Self::NtpServers(_) => OptionCode::NtpServers,
            Self::RequestedIpAddress(_) => OptionCode::RequestedIpAddress,
            Self::AddressLeaseTime(_) => OptionCode::AddressLeaseTime,
            Self::MessageType(_) => OptionCode::MessageType,
            Self::ServerIdentifier(_) => OptionCode::ServerIdentifier,
            Self::ParameterRequestList(_) => OptionCode::ParameterRequestList,
            Self::Message(_) => OptionCode::Message,
            Self::MaxMessageSize(_) => OptionCode::MaxMessageSize,
            Self::Renewal(_) => OptionCode::Renewal,
            Self::Rebinding(_) => OptionCode::Rebinding,
            Self::ClientIdentifier(_) => OptionCode::ClientIdentifier,
            Self::DomainSearch(_) => OptionCode::DomainSearch,
            Self::ClasslessStaticRoute(_) => OptionCode::ClasslessStaticRoute,
        }
    }

    /// Its value, as sent.
    #[must_use]
    fn value(&self) -> Vec<u8> {
        let addresses = |list: &[Ipv4Addr]| list.iter().flat_map(|a| a.octets()).collect();
        match self {
            Self::SubnetMask(address)
            | Self::RequestedIpAddress(address)
            | Self::ServerIdentifier(address) => address.octets().to_vec(),
            Self::Router(list) | Self::DomainNameServer(list) | Self::NtpServers(list) => {
                addresses(list)
            }
            Self::Hostname(text) | Self::DomainName(text) | Self::Message(text) => {
                text.as_bytes().to_vec()
            }
            Self::InterfaceMtu(value) | Self::MaxMessageSize(value) => value.to_be_bytes().to_vec(),
            Self::AddressLeaseTime(value) | Self::Renewal(value) | Self::Rebinding(value) => {
                value.to_be_bytes().to_vec()
            }
            Self::MessageType(kind) => vec![*kind as u8],
            Self::ParameterRequestList(bytes) | Self::ClientIdentifier(bytes) => bytes.clone(),
            Self::DomainSearch(names) => domain_search::encode(names),
            Self::ClasslessStaticRoute(routes) => {
                let mut value = Vec::new();
                for route in routes {
                    let len = route.prefix_len.get();
                    value.push(len);
                    let significant = usize::from(len.div_ceil(8));
                    value.extend_from_slice(&route.destination.octets()[..significant]);
                    let gateway = route.gateway.unwrap_or(Ipv4Addr::UNSPECIFIED);
                    value.extend_from_slice(&gateway.octets());
                }
                value
            }
        }
    }

    /// The option `code` of value `value`; `None` if the value is malformed.
    #[must_use]
    fn decode(code: OptionCode, value: &[u8]) -> Option<Self> {
        Some(match code {
            OptionCode::SubnetMask => Self::SubnetMask(address(value)?),
            OptionCode::Router => Self::Router(addresses(value)?),
            OptionCode::DomainNameServer => Self::DomainNameServer(addresses(value)?),
            OptionCode::Hostname => Self::Hostname(text(value)?),
            OptionCode::DomainName => Self::DomainName(text(value)?),
            OptionCode::InterfaceMtu => Self::InterfaceMtu(u16::from_be_bytes(exact(value)?)),
            OptionCode::NtpServers => Self::NtpServers(addresses(value)?),
            OptionCode::RequestedIpAddress => Self::RequestedIpAddress(address(value)?),
            OptionCode::AddressLeaseTime => {
                Self::AddressLeaseTime(u32::from_be_bytes(exact(value)?))
            }
            OptionCode::MessageType => {
                let [kind] = exact(value)?;
                Self::MessageType(MessageType::from_u8(kind)?)
            }
            OptionCode::ServerIdentifier => Self::ServerIdentifier(address(value)?),
            OptionCode::ParameterRequestList => Self::ParameterRequestList(value.to_vec()),
            OptionCode::Message => Self::Message(text(value)?),
            OptionCode::MaxMessageSize => Self::MaxMessageSize(u16::from_be_bytes(exact(value)?)),
            OptionCode::Renewal => Self::Renewal(u32::from_be_bytes(exact(value)?)),
            OptionCode::Rebinding => Self::Rebinding(u32::from_be_bytes(exact(value)?)),
            OptionCode::ClientIdentifier => Self::ClientIdentifier(value.to_vec()),
            OptionCode::DomainSearch => Self::DomainSearch(
                domain_search::decode(value)?
                    .iter()
                    .filter_map(|name| name.to_ascii_lowercase().parse().ok())
                    .collect(),
            ),
            OptionCode::ClasslessStaticRoute => Self::ClasslessStaticRoute(classless(value)?),
        })
    }
}

/// `value` if it is exactly `N` bytes long.
#[must_use]
fn exact<const N: usize>(value: &[u8]) -> Option<[u8; N]> {
    value.try_into().ok()
}

#[must_use]
fn address(value: &[u8]) -> Option<Ipv4Addr> {
    exact::<4>(value).map(Ipv4Addr::from)
}

/// A non-empty list of addresses.
#[must_use]
fn addresses(value: &[u8]) -> Option<Vec<Ipv4Addr>> {
    let (chunks, rest) = value.as_chunks::<4>();
    (!chunks.is_empty() && rest.is_empty())
        .then(|| chunks.iter().copied().map(Ipv4Addr::from).collect())
}

#[must_use]
fn text(value: &[u8]) -> Option<String> {
    String::from_utf8(value.to_vec()).ok()
}

/// RFC 3442 routes: a prefix length, the significant octets of the destination, the gateway.
#[must_use]
fn classless(mut value: &[u8]) -> Option<Vec<Route>> {
    let mut routes = Vec::new();
    while let Some((&len, rest)) = value.split_first() {
        let prefix_len = PrefixLen::new(len)?;
        let (significant, rest) = rest.split_at_checked(usize::from(len.div_ceil(8)))?;
        let (gateway, rest) = rest.split_first_chunk::<4>()?;
        let mut destination = [0; 4];
        destination[..significant.len()].copy_from_slice(significant);
        let destination = u32::from_be_bytes(destination) & prefix_len.mask();
        let gateway = Ipv4Addr::from(*gateway);
        routes.push(Route {
            destination: destination.into(),
            prefix_len,
            gateway: Some(gateway).filter(|g| !g.is_unspecified()),
        });
        value = rest;
    }
    (!routes.is_empty()).then_some(routes)
}

/// The options of a message, at most one per code.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DhcpOptions(BTreeMap<OptionCode, DhcpOption>);

impl DhcpOptions {
    /// Adds `option`, replacing the option of the same code.
    pub fn insert(&mut self, option: DhcpOption) {
        self.0.insert(option.code(), option);
    }

    /// The option of code `code`.
    #[must_use]
    pub fn get(&self, code: OptionCode) -> Option<&DhcpOption> {
        self.0.get(&code)
    }

    /// The message type (option 53).
    #[must_use]
    pub fn message_type(&self) -> Option<MessageType> {
        match self.get(OptionCode::MessageType) {
            Some(DhcpOption::MessageType(kind)) => Some(*kind),
            _ => None,
        }
    }

    /// Appends the options to `out`, in the order of their codes, then the end option.
    pub fn encode(&self, out: &mut Vec<u8>) {
        for option in self.0.values() {
            let code = option.code() as u8;
            let value = option.value();
            if value.is_empty() {
                out.extend_from_slice(&[code, 0]);
            }
            for chunk in value.chunks(MAX_VALUE_LEN) {
                out.push(code);
                // Chunks of at most 255 bytes: never saturates.
                out.push(u8::try_from(chunk.len()).unwrap_or(u8::MAX));
                out.extend_from_slice(chunk);
            }
        }
        out.push(END);
    }

    /// Decodes the options following the magic cookie, up to the end option (or the end of the
    /// message, which some servers omit it from). The values of options appearing several times
    /// are concatenated (RFC 3396); unknown and malformed options are dropped.
    pub fn decode(mut buf: &[u8]) -> Result<Self, DecodeError> {
        let mut values: BTreeMap<OptionCode, Vec<u8>> = BTreeMap::new();
        while let Some((&code, rest)) = buf.split_first() {
            match code {
                PAD => buf = rest,
                END => break,
                _ => {
                    let (&len, rest) =
                        rest.split_first().ok_or(DecodeError::OptionOverrun(code))?;
                    let (value, rest) = rest
                        .split_at_checked(usize::from(len))
                        .ok_or(DecodeError::OptionOverrun(code))?;
                    if let Some(code) = OptionCode::from_u8(code) {
                        values.entry(code).or_default().extend_from_slice(value);
                    }
                    buf = rest;
                }
            }
        }
        Ok(Self(
            values
                .into_iter()
                .filter_map(|(code, value)| Some((code, DhcpOption::decode(code, &value)?)))
                .collect(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode(buf: &[u8]) -> DhcpOptions {
        DhcpOptions::decode(buf).unwrap()
    }

    fn name(name: &str) -> DomainName {
        name.parse().unwrap()
    }

    #[test]
    fn codes_are_declared_in_numeric_order() {
        assert!(OptionCode::ALL.is_sorted());
        assert!(OptionCode::ALL.map(|code| code as u8).is_sorted());
    }

    #[test]
    fn round_trips() {
        let cases = [
            (
                DhcpOption::SubnetMask([255, 255, 255, 0].into()),
                &[1, 4, 255, 255, 255, 0][..],
            ),
            (
                DhcpOption::Router(vec![[10, 0, 0, 1].into(), [10, 0, 0, 2].into()]),
                &[3, 8, 10, 0, 0, 1, 10, 0, 0, 2],
            ),
            (DhcpOption::Hostname("web-1".into()), b"\x0c\x05web-1"),
            (DhcpOption::InterfaceMtu(1500), &[26, 2, 0x05, 0xdc]),
            (
                DhcpOption::AddressLeaseTime(3600),
                &[51, 4, 0, 0, 0x0e, 0x10],
            ),
            (DhcpOption::MessageType(MessageType::Nak), &[53, 1, 6]),
            (DhcpOption::Message("no".into()), b"\x38\x02no"),
            (DhcpOption::ClientIdentifier(vec![1, 2]), &[61, 2, 1, 2]),
            (DhcpOption::ParameterRequestList(vec![1, 3]), &[55, 2, 1, 3]),
            (
                DhcpOption::DomainSearch(vec![name("a.example"), name("b")]),
                b"\x77\x0e\x01a\x07example\x00\x01b\x00",
            ),
            (
                DhcpOption::ClasslessStaticRoute(vec![
                    Route {
                        destination: [10, 1, 0, 0].into(),
                        prefix_len: PrefixLen::new(16).unwrap(),
                        gateway: Some([10, 0, 0, 254].into()),
                    },
                    Route {
                        destination: Ipv4Addr::UNSPECIFIED,
                        prefix_len: PrefixLen::ZERO,
                        gateway: None,
                    },
                ]),
                &[121, 12, 16, 10, 1, 10, 0, 0, 254, 0, 0, 0, 0, 0],
            ),
        ];
        for (option, wire) in cases {
            let mut options = DhcpOptions::default();
            options.insert(option.clone());
            let mut encoded = Vec::new();
            options.encode(&mut encoded);
            assert_eq!(encoded, [wire, &[END]].concat(), "{option:?}");
            assert_eq!(decode(&encoded).get(option.code()), Some(&option));
        }
    }

    #[test]
    fn skips_padding_and_unknown_options_and_stops_at_end() {
        let options = decode(&[0, 0, 200, 2, 9, 9, 53, 1, 2, 0, END, 53, 1, 5, 99, 99, 99]);
        assert_eq!(options.message_type(), Some(MessageType::Offer));
        assert_eq!(options.0.len(), 1);
        // A missing end option is tolerated.
        assert_eq!(decode(&[53, 1, 5]).message_type(), Some(MessageType::Ack));
        assert_eq!(decode(&[]), DhcpOptions::default());
    }

    #[test]
    fn concatenates_split_options() {
        let options = decode(&[6, 4, 10, 0, 0, 1, 6, 4, 10, 0, 0, 2, END]);
        assert_eq!(
            options.get(OptionCode::DomainNameServer),
            Some(&DhcpOption::DomainNameServer(vec![
                [10, 0, 0, 1].into(),
                [10, 0, 0, 2].into()
            ]))
        );
        // Encoding splits values longer than 255 bytes the same way.
        let long = DhcpOption::ClientIdentifier(vec![7; 300]);
        let mut options = DhcpOptions::default();
        options.insert(long.clone());
        let mut encoded = Vec::new();
        options.encode(&mut encoded);
        assert_eq!(encoded.len(), 2 + 255 + 2 + 45 + 1);
        assert_eq!(
            decode(&encoded).get(OptionCode::ClientIdentifier),
            Some(&long)
        );
    }

    #[test]
    fn rejects_options_running_past_the_end() {
        for buf in [&[53][..], &[53, 1], &[53, 4, 1, 2, 3], &[1, 255]] {
            assert_eq!(
                DhcpOptions::decode(buf),
                Err(DecodeError::OptionOverrun(buf[0])),
                "{buf:?}"
            );
        }
    }

    #[test]
    fn drops_malformed_options() {
        let malformed: &[&[u8]] = &[
            &[1, 3, 255, 255, 0],          // subnet mask of 3 bytes
            &[3, 0],                       // empty router list
            &[6, 5, 1, 2, 3, 4, 5],        // not a multiple of 4
            &[26, 1, 5],                   // MTU of 1 byte
            &[51, 2, 0, 1],                // lease time of 2 bytes
            &[53, 1, 4],                   // DHCPDECLINE, never received
            &[53, 2, 2, 2],                // message type of 2 bytes
            &[12, 2, 0xc3, 0x28],          // invalid UTF-8
            &[121, 5, 33, 0, 0, 0, 0],     // prefix longer than 32
            &[121, 6, 24, 10, 0, 0, 0, 0], // truncated gateway
            &[121, 0],                     // no route
            &[119, 2, 0xc0, 0],            // pointer to itself
        ];
        for buf in malformed {
            let options = decode(buf);
            assert_eq!(options, DhcpOptions::default(), "{buf:?}");
        }
    }

    #[test]
    fn classless_destinations_are_masked() {
        let options = decode(&[121, 6, 8, 10, 10, 0, 0, 1]);
        let Some(DhcpOption::ClasslessStaticRoute(routes)) =
            options.get(OptionCode::ClasslessStaticRoute)
        else {
            panic!("no routes");
        };
        assert_eq!(routes[0].destination, Ipv4Addr::new(10, 0, 0, 0));
        let options = decode(&[121, 8, 12, 10, 0x1f, 10, 0, 0, 1, 0]);
        assert_eq!(options, DhcpOptions::default(), "trailing byte");
        let options = decode(&[121, 7, 12, 10, 0x1f, 10, 0, 0, 1]);
        let Some(DhcpOption::ClasslessStaticRoute(routes)) =
            options.get(OptionCode::ClasslessStaticRoute)
        else {
            panic!("no routes");
        };
        assert_eq!(routes[0].destination, Ipv4Addr::new(10, 16, 0, 0));
    }

    #[test]
    fn search_list_keeps_valid_names_only() {
        let options = decode(b"\x77\x0e\x02OK\x00\x07bad_one\x00\x00");
        assert_eq!(
            options.get(OptionCode::DomainSearch),
            Some(&DhcpOption::DomainSearch(vec![name("ok")]))
        );
    }
}

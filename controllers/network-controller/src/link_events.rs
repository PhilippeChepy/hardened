//! Link notifications (`RTNLGRP_LINK`): links appearing, changing (carrier) and disappearing.

use std::collections::VecDeque;
use std::io;

use netlink_packet_route::RouteNetlinkMessage;
use netlink_packet_route::link::LinkAttribute;
use netlink_packet_route::link::LinkFlags;
use netlink_packet_route::link::LinkMessage;
use rustix::io::Errno;

use crate::netlink_socket;
use crate::netlink_socket::NetlinkSocket;

/// What DHCP needs to know of a link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkState {
    /// Its interface index.
    pub index: u32,
    /// Its kernel name, e.g. `eth0`.
    pub name: String,
    /// Its Ethernet address, if it has one.
    pub mac: Option<[u8; 6]>,
    /// Whether it has a carrier (`IFF_LOWER_UP`).
    pub lower_up: bool,
}

impl LinkState {
    /// The state `msg` describes; `None` without a name, which the kernel always sends.
    #[must_use]
    pub fn from_message(msg: &LinkMessage) -> Option<Self> {
        let mut name = None;
        let mut mac = None;
        for attribute in &msg.attributes {
            match attribute {
                LinkAttribute::IfName(value) => name = Some(value.clone()),
                LinkAttribute::Address(value) => mac = <[u8; 6]>::try_from(value.as_slice()).ok(),
                _ => {}
            }
        }
        Some(Self {
            index: msg.header.index,
            name: name?,
            mac,
            lower_up: msg.header.flags.contains(LinkFlags::LowerUp),
        })
    }
}

/// A link notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkEvent {
    /// `RTM_NEWLINK`: a link appeared or changed.
    Changed(LinkState),
    /// `RTM_DELLINK`: a link disappeared.
    Removed(LinkState),
    /// The kernel dropped notifications: the links must be listed again.
    Lost,
}

/// A subscription to the link notifications.
pub struct LinkEvents {
    socket: NetlinkSocket,
    /// Notifications received but not returned yet.
    pending: VecDeque<LinkEvent>,
}

impl LinkEvents {
    /// Subscribes to the notifications, from now on.
    ///
    /// # Panics
    ///
    /// Outside of a tokio runtime.
    pub fn subscribe() -> io::Result<Self> {
        Ok(Self {
            socket: NetlinkSocket::open(netlink_socket::RTMGRP_LINK)?,
            pending: VecDeque::new(),
        })
    }

    /// The next notification. Cancel safe.
    pub async fn next(&mut self) -> io::Result<LinkEvent> {
        loop {
            if let Some(event) = self.pending.pop_front() {
                return Ok(event);
            }
            match self.socket.notifications().await {
                Ok(messages) => self.pending.extend(messages.iter().filter_map(event)),
                Err(error) if error.raw_os_error() == Some(Errno::NOBUFS.raw_os_error()) => {
                    return Ok(LinkEvent::Lost);
                }
                Err(error) => return Err(error),
            }
        }
    }
}

/// The link event `message` is, if any.
#[must_use]
fn event(message: &RouteNetlinkMessage) -> Option<LinkEvent> {
    match message {
        RouteNetlinkMessage::NewLink(msg) => LinkState::from_message(msg).map(LinkEvent::Changed),
        RouteNetlinkMessage::DelLink(msg) => LinkState::from_message(msg).map(LinkEvent::Removed),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(flags: LinkFlags, attributes: Vec<LinkAttribute>) -> LinkMessage {
        let mut msg = LinkMessage::default();
        msg.header.index = 3;
        msg.header.flags = flags;
        msg.attributes = attributes;
        msg
    }

    #[test]
    fn reads_link_states() {
        let msg = message(
            LinkFlags::Up | LinkFlags::LowerUp,
            vec![
                LinkAttribute::Mtu(1500),
                LinkAttribute::IfName("eth0".into()),
                LinkAttribute::Address(vec![2, 0, 0, 0, 0, 1]),
            ],
        );
        let state = LinkState {
            index: 3,
            name: "eth0".into(),
            mac: Some([2, 0, 0, 0, 0, 1]),
            lower_up: true,
        };
        assert_eq!(LinkState::from_message(&msg), Some(state.clone()));
        assert_eq!(
            event(&RouteNetlinkMessage::NewLink(msg.clone())),
            Some(LinkEvent::Changed(state.clone()))
        );
        assert_eq!(
            event(&RouteNetlinkMessage::DelLink(msg)),
            Some(LinkEvent::Removed(state))
        );

        let no_carrier = message(
            LinkFlags::Up,
            vec![
                LinkAttribute::IfName("ib0".into()),
                LinkAttribute::Address(vec![0; 20]),
            ],
        );
        let state = LinkState::from_message(&no_carrier).unwrap();
        assert!(!state.lower_up);
        assert_eq!(state.mac, None, "not an Ethernet address");

        assert_eq!(
            LinkState::from_message(&message(LinkFlags::Up, vec![])),
            None
        );
        assert_eq!(
            event(&RouteNetlinkMessage::GetLink(LinkMessage::default())),
            None
        );
    }
}

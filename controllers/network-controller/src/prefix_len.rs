//! IPv4 prefix lengths.

use std::fmt;
use std::net::Ipv4Addr;

/// The length of an IPv4 prefix: 0 to 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLen(u8);

impl PrefixLen {
    /// The default route's.
    pub const ZERO: Self = Self(0);
    /// A single address's.
    pub const HOST: Self = Self(32);

    /// `None` past 32.
    #[must_use]
    pub fn new(len: u8) -> Option<Self> {
        (len <= 32).then_some(Self(len))
    }

    /// The length of a subnet mask; `None` if it is not contiguous.
    #[must_use]
    pub fn from_mask(mask: Ipv4Addr) -> Option<Self> {
        let bits = u32::from(mask);
        let ones = bits.leading_ones();
        (ones + bits.trailing_zeros() >= 32).then_some(Self(ones as u8))
    }

    /// The length implied by the address class, for servers omitting the subnet mask.
    #[must_use]
    pub fn classful(address: Ipv4Addr) -> Self {
        Self(match address.octets()[0] {
            0..128 => 8,
            128..192 => 16,
            _ => 24,
        })
    }

    /// The length, for netlink.
    #[must_use]
    pub fn get(self) -> u8 {
        self.0
    }

    /// The subnet mask.
    #[must_use]
    pub fn mask(self) -> u32 {
        u32::MAX.checked_shl(32 - u32::from(self.0)).unwrap_or(0)
    }
}

impl fmt::Display for PrefixLen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subnet_masks() {
        let len = |mask: [u8; 4]| PrefixLen::from_mask(mask.into()).map(PrefixLen::get);
        assert_eq!(len([255, 255, 255, 255]), Some(32));
        assert_eq!(len([255, 255, 240, 0]), Some(20));
        assert_eq!(len([0, 0, 0, 0]), Some(0));
        assert_eq!(len([255, 0, 255, 0]), None);
        assert_eq!(PrefixLen::ZERO.mask(), 0);
        assert_eq!(PrefixLen::HOST.mask(), u32::MAX);
        assert_eq!(PrefixLen::new(20).unwrap().mask(), 0xffff_f000);
        assert_eq!(PrefixLen::new(33), None);
    }
}

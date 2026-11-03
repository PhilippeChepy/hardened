//! Interface MTUs.

use std::fmt;

use serde::Deserialize;
use serde::Serialize;

/// An interface's MTU: from 1280, IPv6's minimum (below, the kernel's SLAAC stops on the
/// interface), to 9216, the largest jumbo frames switches commonly carry. The interface's driver
/// may allow less, which applying it finds out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct Mtu(u16);

impl Mtu {
    /// The smallest.
    pub const MIN: u16 = 1280;
    /// The largest.
    pub const MAX: u16 = 9216;

    /// The MTU, in bytes.
    #[must_use]
    pub fn get(self) -> u16 {
        self.0
    }
}

/// Why an MTU was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("MTU {0} is not from {min} to {max}", min = Mtu::MIN, max = Mtu::MAX)]
pub struct InvalidMtu(pub u32);

impl TryFrom<u32> for Mtu {
    type Error = InvalidMtu;

    fn try_from(mtu: u32) -> Result<Self, Self::Error> {
        u16::try_from(mtu)
            .ok()
            .filter(|mtu| (Self::MIN..=Self::MAX).contains(mtu))
            .map(Self)
            .ok_or(InvalidMtu(mtu))
    }
}

impl From<Mtu> for u32 {
    fn from(mtu: Mtu) -> Self {
        mtu.0.into()
    }
}

impl fmt::Display for Mtu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounds() {
        assert_eq!(Mtu::try_from(1500).unwrap().get(), 1500);
        assert!(Mtu::try_from(1280).is_ok());
        assert!(Mtu::try_from(9216).is_ok());
        for invalid in [0, 576, 1279, 9217, 65536, u32::MAX] {
            assert_eq!(Mtu::try_from(invalid), Err(InvalidMtu(invalid)));
        }
    }
}

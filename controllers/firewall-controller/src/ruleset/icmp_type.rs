//! The ICMP and ICMPv6 types the rules name.

macro_rules! icmp_types {
    ($(#[$doc:meta])* $type:ident { $($variant:ident = $number:literal => $name:literal),+ $(,)? }) => {
        $(#[$doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
        #[allow(missing_docs, reason = "nft's names")]
        pub enum $type {
            $($variant),+
        }

        impl $type {
            /// The type's number.
            #[must_use]
            pub fn number(self) -> u8 {
                match self {
                    $(Self::$variant => $number),+
                }
            }

            /// Its name in nft's syntax.
            #[must_use]
            pub fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $name),+
                }
            }
        }
    };
}

icmp_types!(
    /// The ICMP types the rules name, in increasing order of number.
    IcmpType {
        DestinationUnreachable = 3 => "destination-unreachable",
        EchoRequest = 8 => "echo-request",
        TimeExceeded = 11 => "time-exceeded",
        ParameterProblem = 12 => "parameter-problem",
    }
);

icmp_types!(
    /// The ICMPv6 types the rules name, in increasing order of number.
    Icmpv6Type {
        DestinationUnreachable = 1 => "destination-unreachable",
        PacketTooBig = 2 => "packet-too-big",
        TimeExceeded = 3 => "time-exceeded",
        ParameterProblem = 4 => "parameter-problem",
        EchoRequest = 128 => "echo-request",
        MldListenerQuery = 130 => "mld-listener-query",
        MldListenerReport = 131 => "mld-listener-report",
        NdRouterSolicit = 133 => "nd-router-solicit",
        NdRouterAdvert = 134 => "nd-router-advert",
        NdNeighborSolicit = 135 => "nd-neighbor-solicit",
        NdNeighborAdvert = 136 => "nd-neighbor-advert",
        Mld2ListenerReport = 143 => "mld2-listener-report",
    }
);

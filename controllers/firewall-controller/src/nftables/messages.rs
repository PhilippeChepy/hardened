//! Netlink messages: nfnetlink's header and nf_tables' message kinds.

/// `NFNL_SUBSYS_NFTABLES`.
pub const SUBSYSTEM: u16 = 10;
/// `NFPROTO_INET`.
pub const FAMILY_INET: u8 = 1;
/// `NFNL_MSG_BATCH_BEGIN` (`NLMSG_MIN_TYPE`).
pub const BATCH_BEGIN: u16 = 0x10;
/// `NFNL_MSG_BATCH_END`.
pub const BATCH_END: u16 = 0x11;

/// `NLM_F_*`.
pub mod flags {
    /// A request.
    pub const REQUEST: u16 = 0x1;
    /// Acknowledge it.
    pub const ACK: u16 = 0x4;
    /// Dump everything (`NLM_F_ROOT | NLM_F_MATCH`).
    pub const DUMP: u16 = 0x300;
    /// Create, if it does not exist.
    pub const CREATE: u16 = 0x400;
    /// Append (rules).
    pub const APPEND: u16 = 0x800;
}

/// `NFT_MSG_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageKind {
    /// NFT_MSG_NEWTABLE.
    NewTable = 0,
    /// NFT_MSG_GETTABLE.
    GetTable = 1,
    /// NFT_MSG_DELTABLE.
    DelTable = 2,
    /// NFT_MSG_NEWCHAIN.
    NewChain = 3,
    /// NFT_MSG_NEWRULE.
    NewRule = 6,
    /// NFT_MSG_GETRULE.
    GetRule = 7,
    /// NFT_MSG_NEWSET.
    NewSet = 9,
    /// NFT_MSG_NEWSETELEM.
    NewSetElem = 12,
    /// NFT_MSG_NEWGEN.
    NewGen = 15,
    /// NFT_MSG_GETGEN.
    GetGen = 16,
}

impl MessageKind {
    /// The netlink message type: the subsystem's and the message's.
    #[must_use]
    pub fn netlink_type(self) -> u16 {
        (SUBSYSTEM << 8) | self as u16
    }
}

/// Netlink messages, one after the other, as one datagram.
#[derive(Debug, Default)]
pub struct Messages {
    bytes: Vec<u8>,
    /// The sequence numbers given.
    sequences: Vec<u32>,
    /// What the messages are, by sequence number, for errors.
    labels: Vec<(u32, String)>,
    next_sequence: u32,
}

impl Messages {
    /// No message yet; the first's sequence number is `first_sequence`.
    #[must_use]
    pub fn new(first_sequence: u32) -> Self {
        Self {
            next_sequence: first_sequence,
            ..Self::default()
        }
    }

    /// Appends a message of `netlink_type` with `flags`, nfgenmsg's `family` and `res_id`, and
    /// `attrs`. Returns its sequence number.
    pub fn push(
        &mut self,
        netlink_type: u16,
        flags: u16,
        family: u8,
        res_id: u16,
        attrs: &[u8],
    ) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        // nlmsghdr (16 bytes) and nfgenmsg (4); attributes are padded already.
        let len = u32::try_from(16 + 4 + attrs.len()).unwrap_or(u32::MAX);
        self.bytes.extend_from_slice(&len.to_ne_bytes());
        self.bytes.extend_from_slice(&netlink_type.to_ne_bytes());
        self.bytes.extend_from_slice(&flags.to_ne_bytes());
        self.bytes.extend_from_slice(&sequence.to_ne_bytes());
        // The port: the kernel's to fill.
        self.bytes.extend_from_slice(&0u32.to_ne_bytes());
        // NFNETLINK_V0.
        self.bytes.extend_from_slice(&[family, 0]);
        self.bytes.extend_from_slice(&res_id.to_be_bytes());
        self.bytes.extend_from_slice(attrs);
        self.sequences.push(sequence);
        sequence
    }

    /// Appends an nf_tables request of `kind`.
    pub fn nftables(&mut self, kind: MessageKind, flags: u16, attrs: &[u8]) -> u32 {
        self.push(kind.netlink_type(), flags, FAMILY_INET, 0, attrs)
    }

    /// Names the last message `label`, for the errors the kernel answers it with.
    pub fn label(&mut self, label: impl Into<String>) {
        if let Some(&sequence) = self.sequences.last() {
            self.labels.push((sequence, label.into()));
        }
    }

    /// What the message `sequence` is, if labelled.
    #[must_use]
    pub fn label_of(&self, sequence: u32) -> Option<&str> {
        (self.labels.iter())
            .find(|(labelled, _)| *labelled == sequence)
            .map(|(_, label)| label.as_str())
    }

    /// The datagram.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The sequence numbers of the messages, in order.
    #[must_use]
    pub fn sequences(&self) -> &[u32] {
        &self.sequences
    }

    /// The sequence number the next message gets.
    #[must_use]
    pub fn next_sequence(&self) -> u32 {
        self.next_sequence
    }
}

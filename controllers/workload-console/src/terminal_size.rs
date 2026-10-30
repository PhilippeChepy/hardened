//! Terminal sizes.

use controllers_helpers::InvalidMessage;

use crate::console;

/// A terminal's size in characters, neither dimension zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs, reason = "self-explanatory fields")]
pub struct TerminalSize {
    pub rows: u16,
    pub columns: u16,
}

impl From<TerminalSize> for console::TerminalSize {
    fn from(size: TerminalSize) -> Self {
        Self {
            rows: size.rows.into(),
            columns: size.columns.into(),
        }
    }
}

impl TryFrom<console::TerminalSize> for TerminalSize {
    type Error = InvalidMessage;

    fn try_from(message: console::TerminalSize) -> Result<Self, Self::Error> {
        let dimension = |value: u32, field: &str| {
            u16::try_from(value)
                .ok()
                .filter(|&value| value != 0)
                .ok_or_else(|| InvalidMessage::new(field, "must be between 1 and 65535"))
        };
        Ok(Self {
            rows: dimension(message.rows, "rows")?,
            columns: dimension(message.columns, "columns")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_and_huge_terminals() {
        let size = |rows, columns| TerminalSize::try_from(console::TerminalSize { rows, columns });
        let valid = size(24, 80).unwrap();
        assert_eq!(
            console::TerminalSize::from(valid),
            console::TerminalSize {
                rows: 24,
                columns: 80
            }
        );
        assert_eq!(size(0, 80).unwrap_err().field(), "rows");
        assert_eq!(size(24, 65536).unwrap_err().field(), "columns");
    }
}

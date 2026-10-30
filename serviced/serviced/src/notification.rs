//! What a service's process tells serviced on its notify socket: the systemd notify protocol's
//! newline-separated `KEY=value` assignments. serviced handles `READY=1` and `STATUS=`, and
//! ignores the others (`STOPPING=`, `MAINPID=`, `WATCHDOG=`...).

/// A datagram received on a service's notify socket.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Notification {
    /// `READY=1`: the daemon is ready.
    pub ready: bool,
    /// `STATUS=`: the last one, if any.
    pub status: Option<String>,
}

impl Notification {
    /// Reads `datagram`; what is not UTF-8 is replaced.
    #[must_use]
    pub fn parse(datagram: &[u8]) -> Self {
        let mut notification = Self::default();
        for line in String::from_utf8_lossy(datagram).split('\n') {
            match line.split_once('=') {
                Some(("READY", "1")) => notification.ready = true,
                Some(("STATUS", text)) => notification.status = Some(text.to_owned()),
                _ => {}
            }
        }
        notification
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_assignments() {
        assert_eq!(
            Notification::parse(b"READY=1"),
            Notification {
                ready: true,
                ..Notification::default()
            }
        );
        assert_eq!(
            Notification::parse(b"STATUS=one\nMAINPID=12\nSTATUS=leases: a=b\nSTOPPING=1\n"),
            Notification {
                ready: false,
                status: Some("leases: a=b".to_owned()),
            },
            "the last STATUS wins, unknown keys are ignored, values may hold '='"
        );
        assert_eq!(
            Notification::parse(b"READY=0\nREADY\n\xff=1"),
            Notification::default(),
            "only READY=1 makes ready"
        );
        assert_eq!(
            Notification::parse(b"STATUS=\xffok").status.as_deref(),
            Some("\u{fffd}ok")
        );
    }
}

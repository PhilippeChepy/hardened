//! The methods of serviced's API, and the access each needs (`libserviced::definition::Access`,
//! granted by a service's `api`), as the API's definition says.

use libserviced::definition::Access;

/// A method of `hardened.serviced.v1.Serviced`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    ListServices,
    GetService,
    Start,
    Stop,
    Restart,
    Reload,
    Logs,
    Reboot,
    PowerOff,
    IdentifyProcess,
}

impl Method {
    /// The access the method needs: `read` to look, `control` to change the services or the
    /// machine's power; none for `IdentifyProcess`, open to every service, which authorize the
    /// callers of their own sockets with it.
    #[must_use]
    pub fn access(self) -> Option<Access> {
        match self {
            Self::ListServices | Self::GetService | Self::Logs => Some(Access::Read),
            Self::Start
            | Self::Stop
            | Self::Restart
            | Self::Reload
            | Self::Reboot
            | Self::PowerOff => Some(Access::Control),
            Self::IdentifyProcess => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [Method; 10] = [
        Method::ListServices,
        Method::GetService,
        Method::Start,
        Method::Stop,
        Method::Restart,
        Method::Reload,
        Method::Logs,
        Method::Reboot,
        Method::PowerOff,
        Method::IdentifyProcess,
    ];

    #[test]
    fn access_by_method() {
        let names = |access: Option<Access>| -> Vec<String> {
            ALL.iter()
                .filter(|method| method.access() == access)
                .map(|method| format!("{method:?}"))
                .collect()
        };
        assert_eq!(
            names(Some(Access::Read)),
            ["ListServices", "GetService", "Logs"]
        );
        assert_eq!(
            names(Some(Access::Control)),
            ["Start", "Stop", "Restart", "Reload", "Reboot", "PowerOff"]
        );
        assert_eq!(names(None), ["IdentifyProcess"]);
    }

    #[test]
    fn every_method_of_the_api() {
        let proto = include_str!("../../libserviced/proto/hardened/serviced/v1/serviced.proto");
        let defined: Vec<&str> = proto
            .lines()
            .filter_map(|line| line.trim().strip_prefix("rpc "))
            .filter_map(|rpc| rpc.split('(').next())
            .collect();
        let known: Vec<String> = ALL.iter().map(|method| format!("{method:?}")).collect();
        assert_eq!(defined, known);
    }
}

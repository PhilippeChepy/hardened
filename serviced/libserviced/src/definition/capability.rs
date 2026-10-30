//! A capability a service file keeps.

use serde::{Deserialize, Serialize};

/// A Linux capability, named without `CAP_` (`SYS_TIME`), in the order of their numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[repr(u32)]
#[allow(missing_docs, reason = "named as in Linux")]
pub enum Capability {
    Chown,
    DacOverride,
    DacReadSearch,
    Fowner,
    Fsetid,
    Kill,
    Setgid,
    Setuid,
    Setpcap,
    LinuxImmutable,
    NetBindService,
    NetBroadcast,
    NetAdmin,
    NetRaw,
    IpcLock,
    IpcOwner,
    SysModule,
    SysRawio,
    SysChroot,
    SysPtrace,
    SysPacct,
    SysAdmin,
    SysBoot,
    SysNice,
    SysResource,
    SysTime,
    SysTtyConfig,
    Mknod,
    Lease,
    AuditWrite,
    AuditControl,
    Setfcap,
    MacOverride,
    MacAdmin,
    Syslog,
    WakeAlarm,
    BlockSuspend,
    AuditRead,
    Perfmon,
    Bpf,
    CheckpointRestore,
}

impl Capability {
    /// Its number (`CAP_SYS_TIME` is 25).
    #[must_use]
    pub fn number(self) -> u32 {
        self as u32
    }
}

#[cfg(test)]
mod tests {
    use serde::de::IntoDeserializer;
    use serde::de::value::Error;

    use super::*;

    #[test]
    fn capabilities() {
        let number = |name: &str| {
            Capability::deserialize(name.into_deserializer())
                .map(Capability::number)
                .map_err(|_: Error| ())
                .ok()
        };
        assert_eq!(number("SYS_TIME"), Some(25));
        assert_eq!(number("SYS_TTY_CONFIG"), Some(26));
        assert_eq!(number("CHECKPOINT_RESTORE"), Some(40));
        assert_eq!(number("CAP_SYS_TIME"), None, "named without CAP_");
        assert_eq!(
            toml::Value::try_from(Capability::DacReadSearch).unwrap(),
            toml::Value::String("DAC_READ_SEARCH".into())
        );
    }
}

//! Confinement of a service's processes, from its `[sandbox]`
//! (`libserviced::definition::Sandbox`).
//!
//! A sandboxed process gets:
//! - its own mount, IPC, UTS and cgroup namespaces (it keeps the host network);
//! - a read-only tmpfs root (`pivot_root`) holding only the service's programs (static, like
//!   every program of the image) and its binds: no `/proc`, `/sys`, `/dev`, `/etc`, `/var` or
//!   libraries unless bound, and nothing else to execute;
//! - a uid/gid without supplementary groups, no capability but the service's (in its bounding and
//!   ambient sets, so they survive the `exec`), and `no_new_privs`;
//! - a seccomp allowlist ([`BASE_SYSCALLS`] plus the service's system calls, `socket` limited to
//!   its socket families); any other call kills it. `clone` is limited to threads;
//! - a cgroup (`/sys/fs/cgroup/sandbox/<service>`) capping its memory, tasks and CPU;
//! - implicitly, serviced's socket (every service may call `IdentifyProcess`), its notify socket,
//!   and the sockets of the services whose `allow` names it, with the system calls using them
//!   needs: those of its `notify` and `api`, of serving gRPC on its own `sockets`, and of calling
//!   the sockets it is allowed on.
//!
//! An unconfined service's processes run in its cgroup `/sys/fs/cgroup/services/<service>`: a
//! cgroup is how serviced knows whose a process is ([`caller`](crate::caller)).
//!
//! The sandbox is entered between `fork` and `exec` ([`enter`]), where only async-signal-safe
//! code may run: every path and filter is prepared beforehand ([`Prepared`]); the child only
//! makes system calls on them.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString};
use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, ensure};
use libserviced::definition::{
    AbsolutePath, Bind, Limits, Sandbox, Service, ServiceName, SocketFamily,
};
use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::process::{Gid, Uid};
use rustix::thread::{CapabilitySet, CapabilitySets, UnshareFlags};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use tracing::{debug, info};

const CGROUP_ROOT: &str = "/sys/fs/cgroup";
/// Below [`CGROUP_ROOT`], the cgroups of the sandboxed services, with their limits.
pub const SANDBOX_CGROUPS: &str = "sandbox";
/// Below [`CGROUP_ROOT`], the cgroups of the unconfined services: no limit, only accounting and
/// grouping.
pub const UNCONFINED_CGROUPS: &str = "services";
/// What sending on the notify socket needs, besides a unix socket.
const NOTIFY_SYSCALLS: &[i64] = &[sys::SENDTO];
/// What calling serviced's API needs, besides a unix socket: connecting, the connection's error
/// (`SO_ERROR`, tokio), closing it (`shutdown`, hyper).
const API_SYSCALLS: &[i64] = &[sys::CONNECT, sys::GETSOCKOPT, sys::SHUTDOWN];
/// What serving gRPC on the service's own sockets needs: accepting, the callers' credentials
/// (`SO_PEERCRED`), `IdentifyProcess` on serviced's socket, and the connections' traffic.
const SERVING_SYSCALLS: &[i64] = &[
    sys::ACCEPT4,
    sys::GETSOCKOPT,
    sys::CONNECT,
    sys::RECVFROM,
    sys::SENDTO,
    sys::SHUTDOWN,
];
/// What calling the sockets a service is allowed on needs.
const CALLING_SYSCALLS: &[i64] = &[
    sys::CONNECT,
    sys::GETSOCKOPT,
    sys::RECVFROM,
    sys::SENDTO,
    sys::SHUTDOWN,
];
/// The period of `cpu.max`, in microseconds.
const CPU_PERIOD: u64 = 100_000;
/// The smallest quota of `cpu.max` the kernel takes, in microseconds.
const MIN_CPU_QUOTA: u64 = 1000;
/// Mount points of the sandboxes' roots.
const ROOTS: &str = "/run/serviced/sandbox";

/// What a service's sandbox is made of, from its service file (no file system access).
pub struct Spec {
    /// Names its cgroup and its root.
    name: String,
    /// The service's programs first, then its binds.
    binds: Vec<Bind>,
    /// Its uid and gid.
    user: u32,
    capabilities: CapabilitySet,
    limits: Limits,
    syscalls: Syscalls,
}

/// System calls a program needs, x86-64 numbers.
#[derive(Default)]
struct Syscalls {
    /// Allowed whatever their arguments.
    allowed: Vec<i64>,
    /// Allowed on some argument values only, e.g. `socket`'s domain.
    restricted: Vec<Restriction>,
}

/// A system call allowed only when one of its arguments is one of `values`.
#[derive(Debug, Clone, PartialEq)]
struct Restriction {
    /// Its x86-64 number.
    syscall: i64,
    /// The index of the argument checked.
    argument: u8,
    values: Vec<u64>,
}

impl Spec {
    /// The sandbox of service `name`, defined as `service`, whose `[sandbox]` is `sandbox`. The
    /// sockets of others it uses are bound in at the same path: serviced's (left out while it
    /// does not exist), its notify socket `notify`, and `allowed`, those of the services whose
    /// `allow` names it (each left out while it does not exist: its service is disabled, or its
    /// condition is false).
    pub fn try_new(
        name: &ServiceName,
        service: &Service,
        sandbox: &Sandbox,
        notify: &Path,
        allowed: &[AbsolutePath],
    ) -> anyhow::Result<Self> {
        // Every distinct program, unless a bind already shows it.
        let mut binds: Vec<Bind> = Vec::new();
        let commands = std::iter::once(&service.exec)
            .chain(&service.exec_pre)
            .chain(&service.exec_post)
            .chain(&service.exec_stop);
        for command in commands {
            let program = command.program();
            let shown = binds.iter().any(|bind| bind.path == *program)
                || sandbox
                    .binds
                    .iter()
                    .any(|bind| program.starts_with(&bind.path));
            if !shown {
                binds.push(Bind {
                    path: program.clone(),
                    writable: false,
                    exec: true,
                    device: false,
                    optional: false,
                });
            }
        }
        binds.extend(sandbox.binds.iter().cloned());

        // The sockets of others, unless a bind shows them. Only the notify socket must exist:
        // serviced made it for this run.
        let own = [(notify, false), (Path::new(libserviced::SOCKET), true)]
            .into_iter()
            .map(|(socket, optional)| {
                AbsolutePath::try_from(socket.to_owned()).map(|socket| (socket, optional))
            })
            .collect::<Result<Vec<_>, _>>()
            .context("serviced's sockets")?;
        let others = allowed.iter().map(|socket| (socket.clone(), true));
        for (socket, optional) in own.into_iter().chain(others) {
            let shown = binds.iter().any(|bind| socket.starts_with(&bind.path));
            if !shown {
                binds.push(Bind {
                    path: socket,
                    writable: false,
                    exec: false,
                    device: false,
                    optional,
                });
            }
        }

        let mut capabilities = CapabilitySet::empty();
        for capability in &sandbox.capabilities {
            capabilities |= CapabilitySet::from_bits_retain(1 << capability.number());
        }

        let needs: [(bool, &[i64]); 3] = [
            (!service.api.is_empty(), API_SYSCALLS),
            (!service.sockets.is_empty(), SERVING_SYSCALLS),
            (!allowed.is_empty(), CALLING_SYSCALLS),
        ];
        let implicit = needs
            .into_iter()
            .filter(|(needed, _)| *needed)
            .flat_map(|(_, numbers)| numbers.iter().copied());

        // With socket families, `socket` (and `socketpair`, for unix) is restricted even if
        // listed.
        let mut families: Vec<u64> = sandbox
            .socket_families
            .iter()
            .map(|family| family.number())
            .collect();
        let unix = sandbox.socket_families.contains(&SocketFamily::Unix);
        // The implicit sockets (the notify socket at least) are unix ones, unless `socket` is
        // allowed whatever its family.
        let any_socket = families.is_empty()
            && sandbox
                .syscalls
                .iter()
                .any(|syscall| syscall.number() == sys::SOCKET);
        if !unix && !any_socket {
            families.push(SocketFamily::Unix.number());
        }
        let mut syscalls = Syscalls::default();
        let listed = sandbox.syscalls.iter().map(|syscall| syscall.number());
        let notify = NOTIFY_SYSCALLS.iter().copied();
        for number in listed.chain(notify).chain(implicit) {
            let restricted = match number {
                sys::SOCKET => !families.is_empty(),
                sys::SOCKETPAIR => unix,
                _ => false,
            };
            if !restricted && !syscalls.allowed.contains(&number) {
                syscalls.allowed.push(number);
            }
        }
        if !families.is_empty() {
            syscalls.restricted.push(Restriction {
                syscall: sys::SOCKET,
                argument: 0,
                values: families,
            });
        }
        if unix {
            syscalls.restricted.push(Restriction {
                syscall: sys::SOCKETPAIR,
                argument: 0,
                values: vec![SocketFamily::Unix.number()],
            });
        }
        if !sandbox.ioctls.is_empty() {
            syscalls.restricted.push(Restriction {
                syscall: sys::IOCTL,
                argument: 1,
                values: sandbox.ioctls.iter().map(|ioctl| ioctl.number()).collect(),
            });
        }

        Ok(Self {
            name: name.to_string(),
            binds,
            user: sandbox.user,
            capabilities,
            limits: sandbox.limits,
            syscalls,
        })
    }
}

/// Everything the child needs, computed before `fork`.
pub struct Prepared {
    cgroup_procs: CString,
    root: CString,
    /// Directories to create in the root, parents first.
    dirs: Vec<CString>,
    /// Empty files to create in the root, as mount points of file binds.
    files: Vec<CString>,
    binds: Vec<Mount>,
    /// The uid and gid.
    user: u32,
    capabilities: CapabilitySet,
    filters: Vec<BpfProgram>,
}

impl Prepared {
    /// Prepares the sandbox of `spec`: its cgroup, its root's mount point, and what [`enter`]
    /// needs.
    pub fn try_new(spec: &Spec) -> anyhow::Result<Self> {
        let filters = seccomp_filters(&spec.syscalls)?;
        let cgroup = Path::new(CGROUP_ROOT)
            .join(SANDBOX_CGROUPS)
            .join(&spec.name);
        prepare_cgroup(&cgroup, &spec.limits)?;
        let root = Path::new(ROOTS).join(&spec.name);
        std::fs::create_dir_all(&root).with_context(|| root.display().to_string())?;

        let mut present = Vec::new();
        let mut binds = Vec::new();
        for bind in &spec.binds {
            let metadata = match std::fs::metadata(&bind.path) {
                Ok(metadata) => metadata,
                Err(e) if bind.optional && e.kind() == ErrorKind::NotFound => {
                    debug!(
                        sandbox = %spec.name,
                        path = %bind.path.display(),
                        "optional bind missing, left out"
                    );
                    continue;
                }
                Err(e) => return Err(e).with_context(|| bind.path.display().to_string()),
            };
            present.push((bind.path.as_path(), metadata.is_dir()));
            binds.push(Mount {
                source: c_path(&bind.path)?,
                target: c_path(&in_root(&root, &bind.path))?,
                flags: bind_flags(bind),
            });
        }
        let layout = Layout::new(&root, &present);
        Ok(Self {
            cgroup_procs: c_path(&cgroup.join("cgroup.procs"))?,
            root: c_path(&root)?,
            dirs: c_paths(&layout.dirs)?,
            files: c_paths(&layout.files)?,
            binds,
            user: spec.user,
            capabilities: spec.capabilities,
            filters,
        })
    }
}

/// A bind mount into the root.
struct Mount {
    source: CString,
    /// In the root, before `pivot_root`.
    target: CString,
    flags: MountFlags,
}

/// The flags a bind is remounted with: never setuid; no devices, execution or writes unless
/// the bind allows them.
#[must_use]
fn bind_flags(bind: &Bind) -> MountFlags {
    let mut flags = MountFlags::BIND | MountFlags::NOSUID;
    if !bind.device {
        flags |= MountFlags::NODEV;
    }
    if !bind.exec {
        flags |= MountFlags::NOEXEC;
    }
    if !bind.writable {
        flags |= MountFlags::RDONLY;
    }
    flags
}

/// The mount points to create in the root (`root`, before `pivot_root`) for binds, given each
/// with whether it is a directory.
struct Layout {
    /// Parents before their children.
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
}

impl Layout {
    #[must_use]
    fn new(root: &Path, binds: &[(&Path, bool)]) -> Self {
        // Path order sorts parents before their children.
        let mut dirs = BTreeSet::new();
        let mut files = Vec::new();
        for &(path, is_dir) in binds {
            let parents = path.ancestors().skip(1).filter(|p| *p != Path::new("/"));
            for parent in parents {
                dirs.insert(in_root(root, parent));
            }
            if is_dir {
                dirs.insert(in_root(root, path));
            } else {
                files.push(in_root(root, path));
            }
        }
        Self {
            dirs: dirs.into_iter().collect(),
            files,
        }
    }
}

/// Where host path `path` is in `root`.
#[must_use]
fn in_root(root: &Path, path: &Path) -> PathBuf {
    root.join(path.strip_prefix("/").unwrap_or(path))
}

/// `path` for a system call.
fn c_path(path: &Path) -> anyhow::Result<CString> {
    use std::os::unix::ffi::OsStrExt as _;

    CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("{} contains a NUL", path.display()))
}

/// `paths` for system calls.
fn c_paths(paths: &[PathBuf]) -> anyhow::Result<Vec<CString>> {
    paths.iter().map(|path| c_path(path)).collect()
}

/// Creates `cgroup` with `limits`, enabling the controllers they need.
fn prepare_cgroup(cgroup: &Path, limits: &Limits) -> anyhow::Result<()> {
    let controllers = "+cpu +memory +pids";
    std::fs::write(
        Path::new(CGROUP_ROOT).join("cgroup.subtree_control"),
        controllers,
    )
    .context("enabling the cpu, memory and pids controllers")?;
    let parent = Path::new(CGROUP_ROOT).join(SANDBOX_CGROUPS);
    std::fs::create_dir_all(&parent).with_context(|| parent.display().to_string())?;
    std::fs::write(parent.join("cgroup.subtree_control"), controllers)?;
    std::fs::create_dir_all(cgroup).with_context(|| cgroup.display().to_string())?;
    let settings = [
        (
            "memory.max",
            (u64::from(limits.memory_mib.get()) << 20).to_string(),
        ),
        ("pids.max", limits.tasks.to_string()),
        ("cpu.max", cpu_max(limits.cpu_millicores.get())),
    ];
    for (file, value) in settings {
        let path = cgroup.join(file);
        std::fs::write(&path, value).with_context(|| path.display().to_string())?;
    }
    Ok(())
}

/// The `cpu.max` of `millicores` thousandths of one CPU: the quota and the period, in
/// microseconds.
#[must_use]
fn cpu_max(millicores: u32) -> String {
    let quota = (u64::from(millicores) * CPU_PERIOD / 1000).max(MIN_CPU_QUOTA);
    format!("{quota} {CPU_PERIOD}")
}

/// The `cgroup.procs` of an unconfined service's cgroup, `/sys/fs/cgroup/services/<service>`,
/// created if needed: it groups its processes without limiting them (containerd manages the
/// cgroups of its containers).
pub fn unconfined_cgroup(name: &ServiceName) -> anyhow::Result<CString> {
    let cgroup = Path::new(CGROUP_ROOT)
        .join(UNCONFINED_CGROUPS)
        .join(name.as_str());
    std::fs::create_dir_all(&cgroup).with_context(|| cgroup.display().to_string())?;
    c_path(&cgroup.join("cgroup.procs"))
}

/// Moves the calling process into the cgroup of `procs`. Runs between `fork` and `exec`.
pub fn join_cgroup(procs: &CStr) -> io::Result<()> {
    let procs = rustix::fs::open(procs, OFlags::WRONLY | OFlags::CLOEXEC, Mode::empty())?;
    rustix::io::write(&procs, b"0")?;
    Ok(())
}

/// Enters the sandbox `prepared`. Runs in the child between `fork` and `exec`: no allocation,
/// no lock.
pub fn enter(prepared: &Prepared) -> io::Result<()> {
    // Join the cgroup first: the cgroup namespace is then rooted at it.
    join_cgroup(&prepared.cgroup_procs)?;
    // rustix's safe `unshare` is deprecated: `unshare_unsafe` is the only binding.
    // SAFETY: only `UnshareFlags::FILES` makes `unshare` unsafe (threads may then see file
    // descriptors of another table); it is not among these flags.
    unsafe {
        rustix::thread::unshare_unsafe(
            UnshareFlags::NEWNS
                | UnshareFlags::NEWIPC
                | UnshareFlags::NEWUTS
                | UnshareFlags::NEWCGROUP,
        )?;
    }
    rustix::mount::mount_change(
        c"/",
        MountPropagationFlags::REC | MountPropagationFlags::PRIVATE,
    )?;

    let root = prepared.root.as_c_str();
    rustix::mount::mount(
        c"tmpfs",
        root,
        c"tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        c"mode=0755,size=64k",
    )?;
    for dir in &prepared.dirs {
        rustix::fs::mkdir(dir.as_c_str(), Mode::from_raw_mode(0o755))?;
    }
    for file in &prepared.files {
        drop(rustix::fs::open(
            file.as_c_str(),
            OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )?);
    }
    for bind in &prepared.binds {
        rustix::mount::mount_bind(bind.source.as_c_str(), bind.target.as_c_str())?;
        rustix::mount::mount_remount(bind.target.as_c_str(), bind.flags, c"")?;
    }
    rustix::mount::mount_remount(
        root,
        MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV,
        c"",
    )?;
    rustix::process::chdir(root)?;
    rustix::process::pivot_root(c".", c".")?;
    rustix::mount::unmount(c".", UnmountFlags::DETACH)?;
    rustix::process::chdir(c"/")?;

    // Empty the bounding set but for the kept capabilities while still privileged; the uid
    // change then clears the others (all of them, unless kept, or for root: see below).
    let kept = prepared.capabilities;
    let dropped = CapabilitySet::all().difference(kept);
    for capability in dropped.iter() {
        // `CapabilitySet::all` may name capabilities this kernel does not know: EINVAL.
        match rustix::thread::remove_capability_from_bounding_set(capability) {
            Ok(()) | Err(Errno::INVAL) => {}
            Err(e) => return Err(io::Error::from(e)),
        }
    }
    if !kept.is_empty() {
        rustix::thread::set_keep_capabilities(true)?;
    }
    rustix::thread::set_thread_groups(&[])?;
    let (uid, gid) = (Uid::from_raw(prepared.user), Gid::from_raw(prepared.user));
    rustix::thread::set_thread_res_gid(gid, gid, gid)?;
    rustix::thread::set_thread_res_uid(uid, uid, uid)?;
    rustix::thread::clear_ambient_capability_set()?;
    // Permitted kept through the uid change (or never dropped, for uid 0): only the kept ones
    // stay; inheritable and ambient carry them through the `exec` of a program without file
    // capabilities. For uid 0, the `exec` grants the bounding set: the kept ones.
    rustix::thread::set_keep_capabilities(false)?;
    let sets = CapabilitySets {
        effective: kept,
        permitted: kept,
        inheritable: kept,
    };
    rustix::thread::set_capabilities(None, sets)?;
    for capability in kept.iter() {
        rustix::thread::configure_capability_in_ambient_set(capability, true)?;
    }

    // Sets no_new_privs, then installs each filter; the strictest verdict wins.
    for filter in &prepared.filters {
        seccompiler::apply_filter(filter).map_err(|e| match e {
            seccompiler::Error::Prctl(e) | seccompiler::Error::Seccomp(e) => e,
            _ => io::Error::from(ErrorKind::InvalidInput),
        })?;
    }
    Ok(())
}

/// Logs what the kernel reports of a sandboxed process. The spawn returns after the `exec`, so
/// this is the confinement the program actually runs with (`?` if it already exited).
pub fn log_confinement(service: &ServiceName, program: &str, pid: u32) {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key)?.strip_prefix(':'))
            .map_or("?", str::trim)
            .to_owned()
    };
    let cgroup = std::fs::read_to_string(format!("/proc/{pid}/cgroup")).unwrap_or_default();
    info!(
        service = %service,
        program,
        pid,
        uid = field("Uid"),
        cap_bounding = field("CapBnd"),
        cap_ambient = field("CapAmb"),
        no_new_privs = field("NoNewPrivs"),
        seccomp_filters = field("Seccomp_filters"),
        cgroup = cgroup.trim(),
        "sandboxed process started"
    );
}

/// What any program of the image needs, x86-64: memory, threads, signals, files of the
/// read-only root, polling, time, and the `execve` of the program itself (the filter is
/// installed before it; nothing else is executable in the sandbox).
const BASE_SYSCALLS: &[i64] = &[
    0,   // read
    1,   // write
    2,   // open (musl, where glibc uses openat)
    3,   // close
    4,   // stat
    5,   // fstat
    6,   // lstat
    7,   // poll
    8,   // lseek
    9,   // mmap
    10,  // mprotect
    11,  // munmap
    12,  // brk
    13,  // rt_sigaction
    14,  // rt_sigprocmask
    15,  // rt_sigreturn
    17,  // pread64
    19,  // readv
    20,  // writev
    21,  // access
    24,  // sched_yield
    25,  // mremap
    28,  // madvise
    35,  // nanosleep
    39,  // getpid
    59,  // execve
    60,  // exit
    63,  // uname
    72,  // fcntl
    79,  // getcwd
    89,  // readlink
    96,  // gettimeofday
    99,  // sysinfo (the allocator sizes itself to the machine's memory)
    102, // getuid
    104, // getgid
    107, // geteuid
    108, // getegid
    131, // sigaltstack
    158, // arch_prctl
    186, // gettid
    202, // futex
    204, // sched_getaffinity
    218, // set_tid_address
    219, // restart_syscall
    228, // clock_gettime
    229, // clock_getres
    230, // clock_nanosleep
    231, // exit_group
    232, // epoll_wait
    233, // epoll_ctl
    234, // tgkill
    257, // openat
    262, // newfstatat
    267, // readlinkat
    270, // pselect6
    271, // ppoll
    273, // set_robust_list
    281, // epoll_pwait
    290, // eventfd2
    291, // epoll_create1
    293, // pipe2
    302, // prlimit64
    318, // getrandom
    324, // membarrier
    332, // statx
    334, // rseq
    435, // clone3: answered ENOSYS by the first filter (the strictest verdict wins)
    439, // faccessat2
    441, // epoll_pwait2
];

/// Allowed on some argument values only, for every sandboxed program: the system call, the index
/// of the argument checked, and the values allowed.
const BASE_RESTRICTED: &[(i64, u8, &[u64])] = &[
    // TCGETS, TCGETS2, TIOCGWINSZ (isatty: glibc, Rust, musl), FIONBIO, FIOCLEX.
    (
        sys::IOCTL,
        1,
        &[0x5401, 0x802c_542a, 0x5413, 0x5421, 0x5451],
    ),
    // PR_SET_NAME, PR_GET_NAME (thread names).
    (sys::PRCTL, 0, &[15, 16]),
];

/// x86-64 system call numbers, and the constants their filters check.
mod sys {
    pub const IOCTL: i64 = 16;
    pub const SOCKET: i64 = 41;
    pub const CONNECT: i64 = 42;
    pub const SENDTO: i64 = 44;
    pub const RECVFROM: i64 = 45;
    pub const SHUTDOWN: i64 = 48;
    pub const SOCKETPAIR: i64 = 53;
    pub const GETSOCKOPT: i64 = 55;
    pub const CLONE: i64 = 56;
    pub const PRCTL: i64 = 157;
    pub const ACCEPT4: i64 = 288;
    pub const CLONE3: i64 = 435;
    pub const CLONE_THREAD: u64 = 0x0001_0000;
    pub const ENOSYS: u32 = 38;
}

/// The seccomp filters, in installation order: one failing `clone3` with `ENOSYS`, so the C
/// library falls back to `clone`, whose flags can be checked (threads only, no new processes),
/// then the allowlist (anything else kills the process). Installing a filter is itself a prctl
/// and a seccomp call, which the allowlist forbids: it goes last.
fn seccomp_filters(extra: &Syscalls) -> anyhow::Result<Vec<BpfProgram>> {
    let condition = |argument: u8, op: SeccompCmpOp, value: u64| {
        SeccompCondition::new(argument, SeccompCmpArgLen::Dword, op, value)
            .map_err(anyhow::Error::from)
    };

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    let allowed = BASE_SYSCALLS.iter().chain(&extra.allowed);
    for &syscall in allowed {
        rules.insert(syscall, Vec::new());
    }
    let restricted = extra
        .restricted
        .iter()
        .map(|restriction| {
            let values = restriction.values.as_slice();
            (restriction.syscall, restriction.argument, values)
        })
        .chain(BASE_RESTRICTED.iter().copied());
    for (syscall, argument, values) in restricted {
        // A service listing `ioctl` or `prctl` would lift their restriction.
        ensure!(
            !rules.get(&syscall).is_some_and(Vec::is_empty),
            "system call {syscall} is both allowed and restricted"
        );
        // The service's `ioctls` add to the base set's.
        let alternatives = rules.entry(syscall).or_default();
        for &value in values {
            let condition = condition(argument, SeccompCmpOp::Eq, value)?;
            alternatives.push(SeccompRule::new(vec![condition])?);
        }
    }
    rules.insert(
        sys::CLONE,
        vec![SeccompRule::new(vec![condition(
            0,
            SeccompCmpOp::MaskedEq(sys::CLONE_THREAD),
            sys::CLONE_THREAD,
        )?])?],
    );

    let no_clone3 = SeccompFilter::new(
        BTreeMap::from([(sys::CLONE3, Vec::new())]),
        SeccompAction::Allow,
        SeccompAction::Errno(sys::ENOSYS),
        TargetArch::x86_64,
    )?;
    let allowlist = SeccompFilter::new(
        rules,
        SeccompAction::KillProcess,
        SeccompAction::Allow,
        TargetArch::x86_64,
    )?;
    let no_clone3: BpfProgram = no_clone3.try_into()?;
    let allowlist: BpfProgram = allowlist.try_into()?;
    Ok(vec![no_clone3, allowlist])
}

#[cfg(test)]
mod tests {
    use libserviced::definition;
    use libserviced::definition::Syscall;

    use super::*;

    fn service(text: &str) -> Service {
        toml::from_str(text).unwrap()
    }

    const SERVICED: &str = libserviced::SOCKET;
    const NOTIFY: &str = "/run/serviced/notify/service";

    fn spec_of(name: &ServiceName, service: &Service, allowed: &[AbsolutePath]) -> Spec {
        let sandbox = service.sandbox.as_ref().unwrap();
        Spec::try_new(name, service, sandbox, Path::new(NOTIFY), allowed).unwrap()
    }

    fn number(name: &str) -> i64 {
        name.parse::<Syscall>().unwrap().number()
    }

    #[test]
    fn spec_from_a_service() {
        let service = service(
            r#"
exec = ["/usr/bin/time-controller"]
exec-pre = [["-/usr/bin/time-controller", "--check"], ["/usr/lib/hardened/helper"]]
exec-post = [["/opt/tools/cleanup"]]
[sandbox]
user = 65533
capabilities = ["SYS_TIME"]
socket-families = ["inet", "unix"]
syscalls = ["adjtimex", "bind", "socketpair", "socket", "bind"]
limits.memory-mib = 32
limits.tasks = 4
limits.cpu-millicores = 100
[[sandbox.binds]]
path = "/opt/tools"
exec = true
[[sandbox.binds]]
path = "/dev/tpmrm0"
writable = true
device = true
"#,
        );
        let name: ServiceName = "time-controller".parse().unwrap();
        let spec = spec_of(&name, &service, &[]);
        let paths: Vec<&str> = spec
            .binds
            .iter()
            .map(|bind| bind.path.to_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            [
                "/usr/bin/time-controller",
                "/usr/lib/hardened/helper",
                "/opt/tools",
                "/dev/tpmrm0",
                NOTIFY,
                SERVICED,
            ],
            "each program once, unless a bind shows it"
        );
        assert!(
            spec.binds[0].exec && !spec.binds[0].writable,
            "programs are executable and read-only"
        );
        assert_eq!(spec.user, 65533);
        assert_eq!(spec.capabilities, CapabilitySet::SYS_TIME);
        assert_eq!(
            spec.syscalls.allowed,
            ["adjtimex", "bind", "sendto"].map(number),
            "each once"
        );
        assert_eq!(
            spec.syscalls.restricted,
            [
                Restriction {
                    syscall: sys::SOCKET,
                    argument: 0,
                    values: vec![2, 1],
                },
                Restriction {
                    syscall: sys::SOCKETPAIR,
                    argument: 0,
                    values: vec![1],
                },
            ]
        );
        assert_eq!(seccomp_filters(&spec.syscalls).unwrap().len(), 2);
    }

    #[test]
    fn sockets_to_serviced_are_implicit() {
        let network = service(
            r#"
exec = ["/usr/bin/network-controller"]
notify = true
api = ["read"]
[sandbox]
user = 0
socket-families = ["netlink"]
syscalls = ["bind", "sendto"]
limits.memory-mib = 32
limits.tasks = 4
limits.cpu-millicores = 100
[[sandbox.binds]]
path = "/sys"
"#,
        );
        let name: ServiceName = "network-controller".parse().unwrap();
        let spec = spec_of(&name, &network, &[]);
        let binds: Vec<(&str, bool, bool)> = spec
            .binds
            .iter()
            .map(|bind| (bind.path.to_str().unwrap(), bind.writable, bind.optional))
            .collect();
        assert_eq!(
            binds,
            [
                ("/usr/bin/network-controller", false, false),
                ("/sys", false, false),
                (NOTIFY, false, false),
                (SERVICED, false, true),
            ],
            "read-only: connecting or sending to a socket needs no writable mount"
        );
        assert_eq!(
            spec.syscalls.allowed,
            ["bind", "sendto", "connect", "getsockopt", "shutdown"].map(number)
        );
        assert_eq!(
            spec.syscalls.restricted,
            [Restriction {
                syscall: sys::SOCKET,
                argument: 0,
                values: vec![16, 1],
            }],
            "unix sockets, not socketpair"
        );

        // Without api, only the notify socket's; socket allowed whatever the family stays so.
        let other = service(
            r#"
exec = ["/usr/bin/x"]
[sandbox]
user = 1
syscalls = ["socket"]
limits.memory-mib = 1
limits.tasks = 1
limits.cpu-millicores = 1
"#,
        );
        let spec = spec_of(&name, &other, &[]);
        assert_eq!(spec.binds.len(), 3);
        assert_eq!(spec.syscalls.allowed, ["socket", "sendto"].map(number));
        assert!(spec.syscalls.restricted.is_empty());
    }

    #[test]
    fn serving_and_calling_sockets_is_implicit() {
        let proxy = service(
            r#"
exec = ["/usr/bin/machine-apiproxy"]
[[sockets]]
name = "api"
path = "/run/machine-apiproxy/api.sock"
allow = ["machine-controller"]
[sandbox]
user = 65534
socket-families = ["inet"]
syscalls = ["bind", "listen"]
limits.memory-mib = 128
limits.tasks = 128
limits.cpu-millicores = 500
[[sandbox.binds]]
path = "/run/machine-apiproxy"
writable = true
[[sandbox.binds]]
path = "/run/trust-controller"
"#,
        );
        let name: ServiceName = "machine-apiproxy".parse().unwrap();
        let allowed = [
            "/run/machine-controller/api.sock".parse().unwrap(),
            "/run/trust-controller/api.sock".parse().unwrap(),
        ];
        let spec = spec_of(&name, &proxy, &allowed);
        let binds: Vec<(&str, bool)> = spec
            .binds
            .iter()
            .map(|bind| (bind.path.to_str().unwrap(), bind.optional))
            .collect();
        assert_eq!(
            binds,
            [
                ("/usr/bin/machine-apiproxy", false),
                ("/run/machine-apiproxy", false),
                ("/run/trust-controller", false),
                (NOTIFY, false),
                (SERVICED, true),
                ("/run/machine-controller/api.sock", true),
            ],
            "the allowed sockets, unless a bind shows them; missing ones are left out"
        );
        assert_eq!(
            spec.syscalls.allowed,
            [
                "bind",
                "listen",
                "sendto",
                "accept4",
                "getsockopt",
                "connect",
                "recvfrom",
                "shutdown"
            ]
            .map(number)
        );
        assert_eq!(
            spec.syscalls.restricted,
            [Restriction {
                syscall: sys::SOCKET,
                argument: 0,
                values: vec![2, 1],
            }]
        );

        // A caller only.
        let caller = service(
            r#"
exec = ["/usr/bin/x"]
[sandbox]
user = 1
limits.memory-mib = 1
limits.tasks = 1
limits.cpu-millicores = 1
"#,
        );
        let spec = spec_of(&name, &caller, &allowed);
        assert_eq!(
            spec.syscalls.allowed,
            ["sendto", "connect", "getsockopt", "recvfrom", "shutdown"].map(number)
        );
        assert_eq!(spec.syscalls.restricted[0].values, [1], "unix sockets");
    }

    #[test]
    fn cpu_limits_in_millicores() {
        assert_eq!(cpu_max(1000), "100000 100000", "one CPU");
        assert_eq!(cpu_max(250), "25000 100000");
        assert_eq!(cpu_max(2500), "250000 100000");
        assert_eq!(cpu_max(1), "1000 100000", "the kernel's smallest quota");
    }

    #[test]
    fn listed_system_calls_never_lift_a_restriction() {
        let allowed_and_restricted = Syscalls {
            allowed: vec![sys::PRCTL],
            restricted: vec![],
        };
        assert!(seccomp_filters(&allowed_and_restricted).is_err());
    }

    #[test]
    fn ioctls_add_to_the_base_requests() {
        let ptp = service(
            r#"
exec = ["/usr/bin/x"]
[sandbox]
user = 0
ioctls = ["PTP_SYS_OFFSET"]
limits.memory-mib = 32
limits.tasks = 4
limits.cpu-millicores = 100
"#,
        );
        let spec = spec_of(&"x".parse().unwrap(), &ptp, &[]);
        assert!(spec.syscalls.restricted.contains(&Restriction {
            syscall: sys::IOCTL,
            argument: 1,
            values: vec![0x4340_3d05],
        }));
        assert_eq!(seccomp_filters(&spec.syscalls).unwrap().len(), 2);
    }

    #[test]
    fn layout_mirrors_host_paths() {
        let layout = Layout::new(
            Path::new("/run/serviced/sandbox/x"),
            &[
                (Path::new("/usr/lib"), true),
                (Path::new("/usr/bin/x"), false),
                (Path::new("/run/x/tls"), true),
            ],
        );
        let paths = |paths: &[&str]| -> Vec<PathBuf> { paths.iter().map(PathBuf::from).collect() };
        assert_eq!(
            layout.dirs,
            paths(&[
                "/run/serviced/sandbox/x/run",
                "/run/serviced/sandbox/x/run/x",
                "/run/serviced/sandbox/x/run/x/tls",
                "/run/serviced/sandbox/x/usr",
                "/run/serviced/sandbox/x/usr/bin",
                "/run/serviced/sandbox/x/usr/lib",
            ])
        );
        assert_eq!(layout.files, paths(&["/run/serviced/sandbox/x/usr/bin/x"]));
    }

    #[test]
    fn image_services_make_valid_sandboxes() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../specs/targets/standard/components/system-controllers/services");
        let (services, errors) = definition::load(&[(definition::Layer::Image, &dir)]);
        assert!(errors.is_empty(), "{errors:?}");
        let mut sandboxed = 0;
        for (name, loaded) in &services {
            if loaded.service.sandbox.is_some() {
                let allowed = crate::service_sockets::allowed_sockets(
                    name,
                    services.values().map(|loaded| &loaded.service),
                );
                let spec = spec_of(name, &loaded.service, &allowed);
                seccomp_filters(&spec.syscalls).unwrap_or_else(|e| panic!("{name}: {e:#}"));
                sandboxed += 1;
            }
        }
        assert!(
            sandboxed >= 4,
            "the image's services parsing untrusted input are sandboxed, found {sandboxed}"
        );
    }
}

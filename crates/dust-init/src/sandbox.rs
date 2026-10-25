//! Sandboxed host processes: binaries of the image run by dust-init itself, confined without
//! containerd, and restarted with backoff when they exit.
//!
//! A sandboxed process gets:
//! - its own mount, IPC, UTS and cgroup namespaces (it keeps the host network);
//! - a read-only tmpfs root (`pivot_root`) holding only its program (static, like every program
//!   of the image) and the [`Bind`]s of its [`Spec`]: no `/proc`, `/sys`, `/dev`, `/etc`, `/var`
//!   or libraries, and nothing else to execute;
//! - a uid/gid without supplementary groups, an empty capability bounding set and
//!   `no_new_privs`;
//! - a seccomp allowlist ([`BASE_SYSCALLS`] plus the spec's [`Syscalls`]); any other call kills
//!   it. `clone` is limited to threads;
//! - a cgroup (`/sys/fs/cgroup/sandbox/<name>`) capping its memory, tasks and CPU.
//!
//! The sandbox is entered between `fork` and `exec` ([`enter`]), where only async-signal-safe
//! code may run: every path and filter is prepared beforehand ([`Prepared`]); the child only
//! makes system calls on them.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CString;
use std::io::{BufRead, BufReader};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use rustix::fs::{Mode, OFlags};
use rustix::mount::{MountFlags, MountPropagationFlags, UnmountFlags};
use rustix::process::{Gid, Pid, Signal, Uid};
use rustix::thread::{CapabilitySet, UnshareFlags};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter, SeccompRule, TargetArch,
};
use tokio::sync::oneshot;
use tracing::{info, warn};

use crate::process::{Child, Reaper};

const CGROUPS: &str = "/sys/fs/cgroup/sandbox";
const ROOTS: &str = "/run/sandbox";
/// Restarts back off exponentially up to this, and start over after a run this long.
const MAX_BACKOFF: Duration = Duration::from_secs(60);
const STOP_GRACE: Duration = Duration::from_secs(5);

/// What to run, and what it may see and do.
pub struct Spec {
    /// Names its cgroup, its root and its log lines.
    pub name: &'static str,
    /// Absolute path of the program, in the image; visible at the same path in the sandbox.
    pub program: &'static str,
    pub args: Vec<String>,
    pub env: Vec<(&'static str, String)>,
    /// uid and gid.
    pub id: u32,
    /// Host paths visible read-only at the same path in the sandbox. They must not be nested.
    pub binds: Vec<Bind>,
    pub limits: Limits,
    /// System calls allowed on top of [`BASE_SYSCALLS`].
    pub syscalls: Syscalls,
}

#[derive(Debug, Clone, Copy)]
pub struct Bind {
    pub path: &'static str,
    /// Whether files under it may be executed (or mapped executable).
    pub exec: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub memory_bytes: u64,
    pub tasks: u32,
    /// CPU time per wall-clock time, in percent of one CPU.
    pub cpu_percent: u32,
}

/// System calls a program needs, x86-64 numbers.
#[derive(Debug, Clone, Copy, Default)]
pub struct Syscalls {
    /// Allowed whatever their arguments.
    pub allowed: &'static [i64],
    /// Allowed when an argument (by index) is one of the values, e.g. `socket`'s domain.
    pub restricted: &'static [(i64, u8, &'static [u64])],
}

/// A sandboxed process, supervised: restarted with backoff whenever it exits.
pub struct Supervisor {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl Supervisor {
    pub fn start(reaper: Reaper, spec: Spec) -> anyhow::Result<Self> {
        let prepared =
            Arc::new(Prepared::new(&spec).with_context(|| format!("preparing the sandbox of {}", spec.name))?);
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(supervise(reaper, spec, prepared, stopped));
        Ok(Self { stop, task })
    }

    /// Stops the process (SIGTERM, then SIGKILL) and its supervision.
    pub async fn stop(self) {
        let _ = self.stop.send(());
        let _ = self.task.await;
    }
}

async fn supervise(reaper: Reaper, spec: Spec, prepared: Arc<Prepared>, mut stop: oneshot::Receiver<()>) {
    let name = spec.name;
    let mut backoff = Duration::from_secs(1);
    loop {
        let started = Instant::now();
        match spawn(&reaper, &spec, &prepared) {
            Ok(child) => {
                let pid = child.pid;
                log_confinement(name, pid);
                tokio::select! {
                    exit = child.wait() => warn!(sandbox = name, %exit, "sandboxed process exited"),
                    _ = &mut stop => return terminate(pid).await,
                }
            }
            Err(e) => warn!(sandbox = name, "cannot start the sandboxed process: {e:#}"),
        }
        if started.elapsed() >= MAX_BACKOFF {
            backoff = Duration::from_secs(1);
        }
        tokio::select! {
            () = tokio::time::sleep(backoff) => {}
            _ = &mut stop => return,
        }
        backoff = (backoff * 2).min(MAX_BACKOFF);
    }
}

/// Logs what the kernel reports of the sandbox. `spawn` returns after the `exec`, so this is
/// the confinement the program actually runs with.
fn log_confinement(name: &str, pid: u32) {
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
        sandbox = name,
        pid,
        uid = field("Uid"),
        cap_bounding = field("CapBnd"),
        no_new_privs = field("NoNewPrivs"),
        seccomp_filters = field("Seccomp_filters"),
        cgroup = cgroup.trim(),
        "sandboxed process started"
    );
}

/// SIGTERM, then SIGKILL after [`STOP_GRACE`]. The reaper collects the exit.
async fn terminate(pid: u32) {
    let Some(pid) = Pid::from_raw(pid as i32) else { return };
    let _ = rustix::process::kill_process(pid, Signal::TERM);
    let deadline = Instant::now() + STOP_GRACE;
    while Instant::now() < deadline {
        // Signal 0 only checks that the process still exists.
        if rustix::process::test_kill_process(pid).is_err() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let _ = rustix::process::kill_process(pid, Signal::KILL);
}

fn spawn(reaper: &Reaper, spec: &Spec, prepared: &Arc<Prepared>) -> anyhow::Result<Child> {
    let (reader, writer) = std::io::pipe()?;
    let mut command = Command::new(spec.program);
    command
        .args(&spec.args)
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .stdin(Stdio::null())
        .stdout(writer.try_clone()?)
        .stderr(writer)
        .current_dir("/");
    let prepared = prepared.clone();
    // SAFETY: `enter` only makes system calls on the prepared arguments; it does not allocate
    // or take locks.
    unsafe {
        command.pre_exec(move || enter(&prepared));
    }
    let child = reaper.spawn(&mut command).context("spawning")?;
    // The command holds the write ends: drop them so the reader ends with the process.
    drop(command);
    let name = spec.name;
    std::thread::Builder::new().name(format!("{name}-log")).spawn(move || {
        for line in BufReader::new(reader).lines().map_while(Result::ok) {
            info!("[{name}] {line}");
        }
    })?;
    Ok(child)
}

/// Everything the child needs, computed before `fork`.
struct Prepared {
    cgroup_procs: CString,
    root: CString,
    /// Directories to create in the root, parents first.
    dirs: Vec<CString>,
    /// Empty files to create in the root, as mount points of file binds.
    files: Vec<CString>,
    /// Source, target in the root, and whether it may hold executables.
    binds: Vec<(CString, CString, bool)>,
    id: u32,
    filters: Vec<BpfProgram>,
}

impl Prepared {
    fn new(spec: &Spec) -> anyhow::Result<Self> {
        let cgroup = Path::new(CGROUPS).join(spec.name);
        prepare_cgroup(&cgroup, &spec.limits)?;
        let root = Path::new(ROOTS).join(spec.name);
        std::fs::create_dir_all(&root).with_context(|| root.display().to_string())?;

        let binds: Vec<Bind> = std::iter::once(Bind {
            path: spec.program,
            exec: true,
        })
        .chain(spec.binds.iter().copied())
        .collect();
        for (i, a) in binds.iter().enumerate() {
            ensure!(a.path.starts_with('/'), "{} is not absolute", a.path);
            for b in &binds[i + 1..] {
                let (a, b) = (Path::new(a.path), Path::new(b.path));
                ensure!(
                    !a.starts_with(b) && !b.starts_with(a),
                    "nested binds {} and {}",
                    a.display(),
                    b.display()
                );
            }
        }

        let kinds = binds
            .iter()
            .map(|bind| {
                let metadata = std::fs::metadata(bind.path).with_context(|| bind.path.to_owned())?;
                Ok((*bind, metadata.is_dir()))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let layout = Layout::new(&root, &kinds);
        let c_paths = |paths: &[PathBuf]| paths.iter().map(|p| c_path(p)).collect::<anyhow::Result<Vec<_>>>();

        Ok(Self {
            cgroup_procs: c_path(&cgroup.join("cgroup.procs"))?,
            root: c_path(&root)?,
            dirs: c_paths(&layout.dirs)?,
            files: c_paths(&layout.files)?,
            binds: layout
                .mounts
                .iter()
                .map(|(source, target, exec)| Ok((c_path(source)?, c_path(target)?, *exec)))
                .collect::<anyhow::Result<_>>()?,
            id: spec.id,
            filters: seccomp_filters(&spec.syscalls)?,
        })
    }
}

/// The mount points to create in the root (`root`, before `pivot_root`) for binds, each with
/// whether its source is a directory.
#[derive(Debug, PartialEq, Eq)]
struct Layout {
    /// Parents before their children.
    dirs: Vec<PathBuf>,
    files: Vec<PathBuf>,
    mounts: Vec<(PathBuf, PathBuf, bool)>,
}

impl Layout {
    fn new(root: &Path, binds: &[(Bind, bool)]) -> Self {
        let in_root = |path: &Path| root.join(path.strip_prefix("/").unwrap_or(path));
        // Path order sorts parents before their children.
        let mut dirs = BTreeSet::new();
        let mut files = Vec::new();
        let mut mounts = Vec::new();
        for &(bind, is_dir) in binds {
            let source = Path::new(bind.path);
            let parents = source.ancestors().skip(1).filter(|p| *p != Path::new("/"));
            dirs.extend(parents.map(in_root));
            if is_dir {
                dirs.insert(in_root(source));
            } else {
                files.push(in_root(source));
            }
            mounts.push((source.to_owned(), in_root(source), bind.exec));
        }
        Self {
            dirs: dirs.into_iter().collect(),
            files,
            mounts,
        }
    }
}

fn c_path(path: &Path) -> anyhow::Result<CString> {
    CString::new(path.as_os_str().as_bytes()).with_context(|| format!("{} contains a NUL", path.display()))
}

fn prepare_cgroup(cgroup: &Path, limits: &Limits) -> anyhow::Result<()> {
    let controllers = "+cpu +memory +pids";
    std::fs::write("/sys/fs/cgroup/cgroup.subtree_control", controllers)
        .context("enabling the cpu, memory and pids controllers")?;
    create_dir(Path::new(CGROUPS))?;
    std::fs::write(Path::new(CGROUPS).join("cgroup.subtree_control"), controllers)?;
    create_dir(cgroup)?;
    for (file, value) in [
        ("memory.max", limits.memory_bytes.to_string()),
        ("pids.max", limits.tasks.to_string()),
        ("cpu.max", format!("{} 100000", limits.cpu_percent * 1000)),
    ] {
        let path = cgroup.join(file);
        std::fs::write(&path, value).with_context(|| path.display().to_string())?;
    }
    Ok(())
}

fn create_dir(path: &Path) -> anyhow::Result<()> {
    match std::fs::create_dir(path) {
        Err(e) if e.kind() != std::io::ErrorKind::AlreadyExists => Err(e).context(path.display().to_string()),
        _ => Ok(()),
    }
}

/// Runs in the child between `fork` and `exec`.
fn enter(prepared: &Prepared) -> std::io::Result<()> {
    use rustix::fs::{mkdir, open};
    use rustix::mount::{mount, mount_bind, mount_change, mount_remount, unmount};

    // Join the cgroup first: the cgroup namespace is then rooted at it.
    let procs = open(
        prepared.cgroup_procs.as_c_str(),
        OFlags::WRONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    rustix::io::write(&procs, b"0")?;
    drop(procs);
    // SAFETY: no file descriptor table is unshared.
    unsafe {
        rustix::thread::unshare_unsafe(
            UnshareFlags::NEWNS | UnshareFlags::NEWIPC | UnshareFlags::NEWUTS | UnshareFlags::NEWCGROUP,
        )?;
    }
    mount_change(c"/", MountPropagationFlags::REC | MountPropagationFlags::PRIVATE)?;

    let root = prepared.root.as_c_str();
    mount(
        c"tmpfs",
        root,
        c"tmpfs",
        MountFlags::NOSUID | MountFlags::NODEV,
        c"mode=0755,size=64k",
    )?;
    for dir in &prepared.dirs {
        mkdir(dir.as_c_str(), Mode::from_raw_mode(0o755))?;
    }
    for file in &prepared.files {
        drop(open(
            file.as_c_str(),
            OFlags::CREATE | OFlags::WRONLY | OFlags::CLOEXEC,
            Mode::from_raw_mode(0o644),
        )?);
    }
    for (source, target, exec) in &prepared.binds {
        mount_bind(source.as_c_str(), target.as_c_str())?;
        let mut flags = MountFlags::BIND | MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV;
        if !exec {
            flags |= MountFlags::NOEXEC;
        }
        mount_remount(target.as_c_str(), flags, c"")?;
    }
    mount_remount(root, MountFlags::RDONLY | MountFlags::NOSUID | MountFlags::NODEV, c"")?;
    rustix::process::chdir(root)?;
    rustix::process::pivot_root(c".", c".")?;
    unmount(c".", UnmountFlags::DETACH)?;
    rustix::process::chdir(c"/")?;

    // Empty the bounding set while still privileged; the uid change then clears the others.
    for capability in CapabilitySet::all().iter() {
        match rustix::thread::remove_capability_from_bounding_set(capability) {
            Ok(()) | Err(rustix::io::Errno::INVAL) => {}
            Err(e) => return Err(e.into()),
        }
    }
    rustix::thread::set_thread_groups(&[])?;
    let (uid, gid) = (Uid::from_raw(prepared.id), Gid::from_raw(prepared.id));
    rustix::thread::set_thread_res_gid(gid, gid, gid)?;
    rustix::thread::set_thread_res_uid(uid, uid, uid)?;
    rustix::thread::clear_ambient_capability_set()?;

    // Sets no_new_privs, then installs each filter; the strictest verdict wins.
    for filter in &prepared.filters {
        seccompiler::apply_filter(filter).map_err(|e| match e {
            seccompiler::Error::Prctl(e) | seccompiler::Error::Seccomp(e) => e,
            _ => std::io::Error::from(std::io::ErrorKind::InvalidInput),
        })?;
    }
    Ok(())
}

/// What any program of the image needs, x86-64: memory, threads, signals, files of the
/// read-only root, polling, time, and the `execve` of the program itself (the filter is
/// installed before it; nothing else is executable in the sandbox).
pub const BASE_SYSCALLS: Syscalls = Syscalls {
    allowed: &[
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
    ],
    restricted: &[
        // TCGETS, TCGETS2, TIOCGWINSZ (isatty: glibc, Rust, musl), FIONBIO, FIOCLEX.
        (sys::IOCTL, 1, &[0x5401, 0x802c_542a, 0x5413, 0x5421, 0x5451]),
        // PR_SET_NAME, PR_GET_NAME (thread names).
        (sys::PRCTL, 0, &[15, 16]),
    ],
};

mod sys {
    pub const IOCTL: i64 = 16;
    pub const CLONE: i64 = 56;
    pub const PRCTL: i64 = 157;
    pub const CLONE3: i64 = 435;
    pub const CLONE_THREAD: u64 = 0x0001_0000;
    pub const ENOSYS: u32 = 38;
}

/// The seccomp filters, in installation order: one failing `clone3` with `ENOSYS`, so the C
/// library falls back to `clone`, whose flags can be checked (threads only, no new processes),
/// then the allowlist (anything else kills the process). Installing a filter is itself a prctl
/// and a seccomp call, which the allowlist forbids: it goes last.
fn seccomp_filters(extra: &Syscalls) -> anyhow::Result<Vec<BpfProgram>> {
    let arg = |index: u8, op: SeccompCmpOp, value: u64| {
        SeccompCondition::new(index, SeccompCmpArgLen::Dword, op, value).map_err(anyhow::Error::from)
    };

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BASE_SYSCALLS
        .allowed
        .iter()
        .chain(extra.allowed)
        .map(|&nr| (nr, Vec::new()))
        .collect();
    let mut restricted: BTreeMap<i64, (u8, BTreeSet<u64>)> = BTreeMap::new();
    for &(nr, index, values) in BASE_SYSCALLS.restricted.iter().chain(extra.restricted) {
        ensure!(
            !rules.contains_key(&nr),
            "system call {nr} is both allowed and restricted"
        );
        let (existing, set) = restricted.entry(nr).or_insert((index, BTreeSet::new()));
        if *existing != index {
            bail!("system call {nr} is restricted on two arguments");
        }
        set.extend(values);
    }
    for (nr, (index, values)) in restricted {
        let alternatives = values
            .into_iter()
            .map(|v| Ok(SeccompRule::new(vec![arg(index, SeccompCmpOp::Eq, v)?])?))
            .collect::<anyhow::Result<_>>()?;
        rules.insert(nr, alternatives);
    }
    rules.insert(
        sys::CLONE,
        vec![SeccompRule::new(vec![arg(
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
    Ok(vec![no_clone3.try_into()?, allowlist.try_into()?])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filters_merge_restrictions() {
        const EXTRA: Syscalls = Syscalls {
            allowed: &[42],
            restricted: &[(sys::IOCTL, 1, &[0x1234]), (41, 0, &[1, 2])],
        };
        let filters = seccomp_filters(&EXTRA).unwrap();
        assert_eq!(filters.len(), 2);
        assert!(filters.iter().all(|f| !f.is_empty() && f.len() < usize::from(u16::MAX)));
    }

    #[test]
    fn conflicting_restrictions_are_rejected() {
        const ON_ANOTHER_ARGUMENT: Syscalls = Syscalls {
            allowed: &[],
            restricted: &[(sys::IOCTL, 0, &[1])],
        };
        assert!(seccomp_filters(&ON_ANOTHER_ARGUMENT).is_err());
        const ALLOWED_AND_RESTRICTED: Syscalls = Syscalls {
            allowed: &[sys::PRCTL],
            restricted: &[],
        };
        assert!(seccomp_filters(&ALLOWED_AND_RESTRICTED).is_err());
    }

    #[test]
    fn layout_mirrors_host_paths() {
        let bind = |path, exec| Bind { path, exec };
        let layout = Layout::new(
            Path::new("/run/sandbox/x"),
            &[
                (bind("/usr/lib", true), true),
                (bind("/usr/bin/x", true), false),
                (bind("/run/x/tls", false), true),
            ],
        );
        let paths = |paths: &[&str]| paths.iter().map(PathBuf::from).collect::<Vec<_>>();
        assert_eq!(
            layout.dirs,
            paths(&[
                "/run/sandbox/x/run",
                "/run/sandbox/x/run/x",
                "/run/sandbox/x/run/x/tls",
                "/run/sandbox/x/usr",
                "/run/sandbox/x/usr/bin",
                "/run/sandbox/x/usr/lib",
            ])
        );
        assert_eq!(layout.files, paths(&["/run/sandbox/x/usr/bin/x"]));
        assert_eq!(
            layout.mounts[2],
            ("/run/x/tls".into(), "/run/sandbox/x/run/x/tls".into(), false)
        );
    }
}

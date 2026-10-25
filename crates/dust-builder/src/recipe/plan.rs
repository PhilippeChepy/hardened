//! Build plans: what a recipe's build does, as data.
//!
//! A recipe describes its `fetch` and `build` phases through [`Build`]; nothing runs while it
//! does. The resulting [`Plan`] is printed by `cargo builder plan`, hashed into the cache key and
//! executed step by step in the builder container ([`crate::exec`]). Paths are [`Loc`]ations
//! relative to a few well-known places (scratch space, the OS root, the component's outputs...),
//! and steps may only write to the component's own places.
//!
//! While describing the build, recipes also declare what it uses: [`Build::source`] records a
//! [`Source`], [`Build::input`] another component's tree or output (a dependency).

use std::collections::BTreeSet;
use std::fmt::{self, Write as _};

use super::output::Output;
use super::{ComponentName, ContainerImage, Source, Unit};
use crate::sbom::Inventory;

/// Where a [`Loc`] is relative to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base {
    /// Scratch space of the build.
    Work,
    /// The repository checkout (read-only).
    Repo,
    /// The downloaded sources (read-only).
    Sources,
    /// The component's tree, installed at `/` (in the image, or in the environments holding it).
    Root,
    /// One of the component's container images.
    Image(ComponentName),
    /// The component's typed outputs.
    Outputs,
    /// Inventories for the SBOM.
    Sbom,
    /// Another component's directory (read-only): its tree at `root`, its outputs at `outputs/`.
    Dep(Unit),
    /// Kept across builds of the component (e.g. cargo's target directory).
    Cache,
    /// Secrets from `build/keys/` the build declared (read-only).
    Secrets,
}

/// A path relative to a [`Base`]. Its segments may hold `*` and `?` wildcards and `**` (any
/// number of directories), resolved when the step runs, for the steps that accept patterns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loc {
    base: Base,
    /// Relative, `/`-separated; empty for the base itself.
    path: String,
}

impl Loc {
    fn new(base: Base) -> Self {
        Self {
            base,
            path: String::new(),
        }
    }

    /// `self/path`. Panics unless `path` is relative, without empty, `.` or `..` segments: a
    /// recipe bug, caught when recipes load.
    pub fn join(&self, path: &str) -> Self {
        let valid = !path.is_empty()
            && !path.contains('\0')
            && path.split('/').all(|segment| !matches!(segment, "" | "." | ".."));
        assert!(valid, "{path:?} is not a relative path without '.' or '..'");
        let path = if self.path.is_empty() {
            path.to_owned()
        } else {
            format!("{}/{path}", self.path)
        };
        Self {
            base: self.base.clone(),
            path,
        }
    }

    pub fn base(&self) -> &Base {
        &self.base
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn is_pattern(&self) -> bool {
        self.path.contains(['*', '?'])
    }

    fn writable(&self) -> bool {
        !matches!(self.base, Base::Repo | Base::Sources | Base::Dep(_) | Base::Secrets)
    }
}

impl fmt::Display for Loc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let path = if self.path.is_empty() { "." } else { &self.path };
        match &self.base {
            Base::Root => write!(f, "root:/{}", self.path),
            Base::Image(name) => write!(f, "image({name}):/{}", self.path),
            Base::Dep(name) => write!(f, "dep({name}):{path}"),
            Base::Work => write!(f, "work:{path}"),
            Base::Repo => write!(f, "repo:{path}"),
            Base::Sources => write!(f, "sources:{path}"),
            Base::Outputs => write!(f, "out:{path}"),
            Base::Sbom => write!(f, "sbom:{path}"),
            Base::Cache => write!(f, "cache:{path}"),
            Base::Secrets => write!(f, "secret:{path}"),
        }
    }
}

/// A command argument: literal text, locations, and values known when the step runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Arg(Vec<Piece>);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Piece {
    Text(String),
    Loc(Loc),
    /// The number of parallel jobs.
    Jobs,
    /// `SOURCE_DATE_EPOCH`, the timestamp of reproducible outputs.
    Epoch,
}

impl Arg {
    /// The number of parallel jobs.
    pub fn jobs() -> Self {
        Self(vec![Piece::Jobs])
    }

    /// `SOURCE_DATE_EPOCH`, the timestamp of reproducible outputs.
    pub fn epoch() -> Self {
        Self(vec![Piece::Epoch])
    }

    /// `self` immediately followed by `other`. Adjacent texts merge, so an argument has one
    /// form (and one cache key) however it was put together.
    pub fn concat(mut self, other: impl Into<Arg>) -> Self {
        for piece in other.into().0 {
            match (self.0.last_mut(), piece) {
                (Some(Piece::Text(text)), Piece::Text(more)) => text.push_str(&more),
                (_, piece) => self.0.push(piece),
            }
        }
        self
    }

    pub fn pieces(&self) -> &[Piece] {
        &self.0
    }

    fn locs(&self) -> impl Iterator<Item = &Loc> {
        self.0.iter().filter_map(|piece| match piece {
            Piece::Loc(loc) => Some(loc),
            _ => None,
        })
    }
}

impl From<&str> for Arg {
    fn from(text: &str) -> Self {
        Self(vec![Piece::Text(text.to_owned())])
    }
}

impl From<String> for Arg {
    fn from(text: String) -> Self {
        Self(vec![Piece::Text(text)])
    }
}

impl From<&Loc> for Arg {
    fn from(loc: &Loc) -> Self {
        Self(vec![Piece::Loc(loc.clone())])
    }
}

impl From<Loc> for Arg {
    fn from(loc: Loc) -> Self {
        Self(vec![Piece::Loc(loc)])
    }
}

impl fmt::Display for Arg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut text = String::new();
        for piece in &self.0 {
            match piece {
                Piece::Text(t) => text.push_str(t),
                Piece::Loc(loc) => {
                    let _ = write!(text, "{loc}");
                }
                Piece::Jobs => text.push_str("{jobs}"),
                Piece::Epoch => text.push_str("{epoch}"),
            }
        }
        if text.is_empty() || text.contains(char::is_whitespace) {
            write!(f, "'{text}'")
        } else {
            f.write_str(&text)
        }
    }
}

/// A program run in the builder container, without a shell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    pub program: Arg,
    pub args: Vec<Arg>,
    pub dir: Loc,
    pub env: Vec<(String, Arg)>,
}

impl fmt::Display for Command {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (key, value) in &self.env {
            write!(f, "{key}={value} ")?;
        }
        write!(f, "{}", self.program)?;
        for arg in &self.args {
            write!(f, " {arg}")?;
        }
        if self.dir != Loc::new(Base::Work) {
            write!(f, "  (in {})", self.dir)?;
        }
        Ok(())
    }
}

/// Permission bits of an installed file. Setuid, setgid and sticky bits cannot be expressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode(u32);

impl Mode {
    pub const FILE: Self = Self::new(0o644);
    pub const EXECUTABLE: Self = Self::new(0o755);

    pub const fn new(mode: u32) -> Self {
        assert!(mode <= 0o777, "only permission bits: no setuid, setgid or sticky bit");
        Self(mode)
    }

    pub fn bits(self) -> u32 {
        self.0
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04o}", self.0)
    }
}

/// One step of a plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Extracts an archive into `into` (its single top-level directory, if it has one).
    Unpack {
        archive: Loc,
        into: Loc,
    },
    Mkdir(Loc),
    Run(Command),
    /// Runs a command and writes its standard output to a file.
    Capture {
        command: Command,
        into: Loc,
    },
    Write {
        to: Loc,
        contents: String,
        mode: Mode,
    },
    /// Applies the unified diff `diff` (named `name`) to the source tree `tree`, as `patch -p1`
    /// without fuzz ([`crate::patch`]).
    Patch {
        tree: Loc,
        name: String,
        diff: String,
    },
    /// Installs one file; `from` may be a pattern matching exactly one file.
    Install {
        from: Loc,
        to: Loc,
        mode: Mode,
    },
    /// Copies every match of `from` (at least one) into the directory `into`, preserving
    /// symbolic links and modes.
    Copy {
        from: Loc,
        into: Loc,
    },
    Symlink {
        target: String,
        link: Loc,
    },
    /// Removes every file or symbolic link matching the pattern (possibly none).
    Remove(Loc),
    /// Strips debug information from the ELF files of the root filesystem.
    Strip,
    /// Fails if the tree `env` has a real `bin`, `sbin`, `lib` or `lib64` directory at its root:
    /// copied into an environment, it would replace the merged-`/usr` symbolic link there.
    CheckEnv(Loc),
    /// Fails unless every `CONFIG_X=v` line of `fragment` is in the kernel `config`, and every
    /// `CONFIG_X=n` absent from it: Kconfig silently drops options whose dependencies are unmet.
    CheckKernelConfig {
        config: Loc,
        fragment: String,
    },
}

impl fmt::Display for Step {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unpack { archive, into } => write!(f, "unpack   {archive} → {into}"),
            Self::Mkdir(dir) => write!(f, "mkdir    {dir}"),
            Self::Run(command) => write!(f, "run      {command}"),
            Self::Capture { command, into } => write!(f, "capture  {command} → {into}"),
            Self::Write { to, contents, mode } => {
                let shown = if contents.len() <= 60 && !contents.trim_end().contains('\n') {
                    format!("{:?}", contents)
                } else {
                    format!("{} lines", contents.lines().count())
                };
                write!(f, "write    {to} ({mode}) = {shown}")
            }
            Self::Patch { tree, name, .. } => write!(f, "patch    {tree} with {name}"),
            Self::Install { from, to, mode } => write!(f, "install  {from} → {to} ({mode})"),
            Self::Copy { from, into } => write!(f, "copy     {from} → {into}/"),
            Self::Symlink { target, link } => write!(f, "symlink  {link} → {target}"),
            Self::Remove(path) => write!(f, "remove   {path}"),
            Self::CheckEnv(env) => write!(f, "check    {env} keeps the merged-/usr layout"),
            Self::Strip => write!(f, "strip    root:/ (debug information of ELF files)"),
            Self::CheckKernelConfig { config, fragment } => {
                let options = fragment.lines().filter(|l| l.starts_with("CONFIG_")).count();
                write!(f, "check    {config} has the {options} options of the fragment")
            }
        }
    }
}

/// What a component's build does and uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Steps run with network access before the build (lockfile-verified downloads only).
    pub fetch: Vec<Step>,
    /// Steps run without network access.
    pub build: Vec<Step>,
    /// Source archives, in order of first use.
    pub sources: Vec<Source>,
    /// The container images the build fills, archived after it.
    pub images: Vec<ContainerImage>,
    /// Files of `build/keys/` the build uses; only these are visible to it.
    pub secrets: Vec<&'static str>,
    /// The outputs the build writes, by name.
    pub outputs: BTreeSet<&'static str>,
    /// The trees (`None`) and outputs of other components it reads, checked against what those
    /// write.
    pub uses: BTreeSet<(Unit, Option<&'static str>)>,
}

impl Plan {
    /// The units whose trees or outputs the build reads: its dependencies.
    pub fn inputs(&self) -> BTreeSet<&Unit> {
        self.uses.iter().map(|(unit, _)| unit).collect()
    }
}

impl Plan {
    /// Describes the phases of a component.
    pub(super) fn describe(
        name: &ComponentName,
        fetch: impl FnOnce(&mut Build) -> anyhow::Result<()>,
        build: impl FnOnce(&mut Build) -> anyhow::Result<()>,
    ) -> anyhow::Result<Self> {
        let mut b = Build::new(name.clone());
        fetch(&mut b)?;
        let fetch = std::mem::take(&mut b.steps);
        build(&mut b)?;
        // The tree goes onto `/`: it must keep the merged-`/usr` layout.
        b.step(Step::CheckEnv(Loc::new(Base::Root)));
        if !b.errors.is_empty() {
            anyhow::bail!("invalid plan:\n  {}", b.errors.join("\n  "));
        }
        Ok(Self {
            fetch,
            build: b.steps,
            sources: b.sources,
            images: b.images,
            secrets: b.secrets,
            outputs: b.outputs,
            uses: b.uses,
        })
    }
}

impl fmt::Display for Plan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if !self.sources.is_empty() {
            writeln!(f, "sources:")?;
            for source in &self.sources {
                writeln!(f, "  {}  sha256:{}", source.url, source.sha256)?;
            }
        }
        let inputs = self.inputs();
        if !inputs.is_empty() {
            let inputs: Vec<String> = inputs.iter().map(ToString::to_string).collect();
            writeln!(f, "uses: {}", inputs.join(", "))?;
        }
        for image in &self.images {
            writeln!(f, "container image: {} (entrypoint {})", image.name, image.entrypoint)?;
        }
        for secret in &self.secrets {
            writeln!(f, "secret: build/keys/{secret}")?;
        }
        if !self.fetch.is_empty() {
            writeln!(f, "fetch (with network):")?;
            for step in &self.fetch {
                writeln!(f, "  {step}")?;
            }
        }
        writeln!(f, "build (offline):")?;
        for step in &self.build {
            writeln!(f, "  {step}")?;
        }
        Ok(())
    }
}

/// cgo for [`Build::go_build`].
#[derive(Debug, Clone)]
pub enum Cgo {
    /// Pure Go: a static binary without libc.
    Disabled,
    /// Links statically against musl and C libraries: a static PIE, with full RELRO, its C code
    /// with ThinLTO. `libraries` holds other libraries' staged `/usr` tree (a dependency's output,
    /// static archives only), found through pkg-config.
    Enabled { libraries: Option<Loc> },
}

/// A Go binary for [`Build::go_build`]. Dependencies must be vendored (builds are offline).
#[derive(Debug, Clone)]
pub struct GoBuild<'a> {
    pub tree: &'a Loc,
    /// Package to build, relative to `tree` (`.` or `./cmd/x`).
    pub package: &'a str,
    /// Absolute path in the root filesystem.
    pub install: &'a str,
    pub cgo: Cgo,
    pub tags: &'a [&'a str],
    /// Link-time `-X` variables.
    pub vars: &'a [(&'a str, &'a str)],
}

/// The Rust target of workspace binaries (the build machine's).
const RUST_TARGET: &str = "x86_64-unknown-linux-musl";
/// The image's binaries are static PIEs (musl, mimalloc and libunwind linked in, with the
/// workspace's release LTO). With `--target`, `RUSTFLAGS` leaves build scripts and proc macros
/// alone: they run on the build machine, dynamically linked.
const RUST_STATIC: &str = "-C target-feature=+crt-static";
/// A binary of the repository workspace, named like its package, statically linked.
#[derive(Debug, Clone, Copy)]
pub struct CargoBinary {
    pub package: &'static str,
    /// Absolute path in the root filesystem.
    pub install: &'static str,
}

/// The build of a component being described. Every method appends steps to the plan.
pub struct Build {
    name: ComponentName,
    steps: Vec<Step>,
    sources: Vec<Source>,
    images: Vec<ContainerImage>,
    secrets: Vec<&'static str>,
    outputs: BTreeSet<&'static str>,
    uses: BTreeSet<(Unit, Option<&'static str>)>,
    /// Misuses found while describing the build, reported all at once.
    errors: Vec<String>,
}

impl Build {
    fn new(name: ComponentName) -> Self {
        Self {
            name,
            steps: Vec::new(),
            sources: Vec::new(),
            images: Vec::new(),
            secrets: Vec::new(),
            outputs: BTreeSet::new(),
            uses: BTreeSet::new(),
            errors: Vec::new(),
        }
    }

    /// A build of component `x`, for tests describing a plan by hand.
    #[cfg(test)]
    pub(crate) fn for_tests() -> Self {
        Self::new(crate::name!("x"))
    }

    /// The steps described so far.
    #[cfg(test)]
    pub(crate) fn into_steps(self) -> Vec<Step> {
        self.steps
    }

    /// A location in scratch space.
    pub fn work(&self, path: &str) -> Loc {
        Loc::new(Base::Work).join(path)
    }

    /// The repository checkout, for in-tree components.
    pub fn repository(&self) -> Loc {
        Loc::new(Base::Repo)
    }

    /// A location kept across builds of this component.
    pub fn cache(&self, path: &str) -> Loc {
        Loc::new(Base::Cache).join(path)
    }

    /// `path` (absolute) in the OS root filesystem.
    pub fn root(&mut self, path: &str) -> Loc {
        let root = Loc::new(Base::Root);
        match path.strip_prefix('/') {
            Some("") => root,
            Some(relative) if !relative.ends_with('/') => root.join(relative),
            _ => {
                self.errors.push(format!("{path:?} is not an absolute path"));
                root
            }
        }
    }

    /// The location of one of this component's outputs.
    pub fn output(&mut self, output: &Output) -> Loc {
        if *output.component() != self.name {
            self.errors.push(format!("{output} is an output of another component"));
        }
        self.outputs.insert(output.name());
        Loc::new(Base::Outputs).join(output.name())
    }

    /// Another component's tree (`output` `None`) or output; using it makes that component a
    /// dependency.
    pub fn input(&mut self, unit: &Unit, output: Option<&'static str>) -> Loc {
        self.uses.insert((unit.clone(), output));
        let dep = Loc::new(Base::Dep(unit.clone()));
        match output {
            None => dep.join("root"),
            Some(name) => dep.join("outputs").join(name),
        }
    }

    /// Declares a container image the build fills (archived after it), returning its root.
    pub fn container_image(&mut self, image: &ContainerImage) -> Loc {
        if !self.images.contains(image) {
            self.images.push(image.clone());
        }
        Loc::new(Base::Image(image.name.clone()))
    }

    /// A file of `build/keys/` (e.g. a signing key), made visible to this build only. Its
    /// contents are hashed into the cache key, never shipped.
    pub fn secret(&mut self, name: &'static str) -> Loc {
        if name.is_empty() || name.starts_with('.') || name.contains(['/', '\0']) {
            self.errors.push(format!("secret {name:?} is not a file name"));
        }
        if !self.secrets.contains(&name) {
            self.secrets.push(name);
        }
        Loc::new(Base::Secrets).join(name)
    }

    /// A source file, recorded as one of the component's sources.
    pub fn source(&mut self, source: &Source) -> Loc {
        if !self.sources.contains(source) {
            self.sources.push(*source);
        }
        Loc::new(Base::Sources).join(&source.sha256.to_string())
    }

    /// Extracts a source archive into `work:<name>`, returning that directory.
    pub fn unpack(&mut self, source: &Source, name: &str) -> Loc {
        let archive = self.source(source);
        let into = self.work(name);
        self.step(Step::Unpack {
            archive,
            into: into.clone(),
        });
        into
    }

    /// A command, run in scratch space unless [`Cmd::dir`] says otherwise.
    pub fn cmd(&mut self, program: impl Into<Arg>) -> Cmd<'_> {
        Cmd {
            build: self,
            command: Command {
                program: program.into(),
                args: Vec::new(),
                dir: Loc::new(Base::Work),
                env: Vec::new(),
            },
        }
    }

    /// `make -j{jobs}` in `dir`; add the targets as arguments.
    pub fn make(&mut self, dir: &Loc) -> Cmd<'_> {
        let jobs = Arg::from("-j").concat(Arg::jobs());
        self.cmd("make").dir(dir).arg(jobs)
    }

    pub fn mkdir(&mut self, dir: &Loc) {
        self.destination(dir);
        self.step(Step::Mkdir(dir.clone()));
    }

    pub fn write(&mut self, to: &Loc, contents: impl Into<String>, mode: Mode) {
        self.destination(to);
        self.step(Step::Write {
            to: to.clone(),
            contents: contents.into(),
            mode,
        });
    }

    /// Applies the patch `diff`, the file `name` of the recipe's directory, to the source `tree`.
    pub fn patch(&mut self, tree: &Loc, name: &str, diff: &str) {
        self.destination(tree);
        self.step(Step::Patch {
            tree: tree.clone(),
            name: name.to_owned(),
            diff: diff.to_owned(),
        });
    }

    /// Installs one file; `from` may be a pattern matching exactly one file.
    pub fn install(&mut self, from: &Loc, to: &Loc, mode: Mode) {
        self.destination(to);
        self.step(Step::Install {
            from: from.clone(),
            to: to.clone(),
            mode,
        });
    }

    /// Copies every match of `from` (at least one; e.g. `dir/*` for a directory's contents)
    /// into the directory `into`.
    pub fn copy(&mut self, from: &Loc, into: &Loc) {
        self.destination(into);
        self.step(Step::Copy {
            from: from.clone(),
            into: into.clone(),
        });
    }

    /// Creates the symbolic link `link` pointing to `target` (relative to the link's directory).
    pub fn symlink(&mut self, target: &str, link: &Loc) {
        self.destination(link);
        self.step(Step::Symlink {
            target: target.to_owned(),
            link: link.clone(),
        });
    }

    /// Removes the files or symbolic links matching `path` (possibly none).
    pub fn remove(&mut self, path: &Loc) {
        self.destination(path);
        self.step(Step::Remove(path.clone()));
    }

    /// Builds a Go binary into the root filesystem with the hardened defaults (vendored,
    /// `-trimpath`, stripped) and records its modules for the SBOM.
    pub fn go_build(&mut self, go: GoBuild<'_>) {
        let mut ldflags = String::from("-s -w");
        for (name, value) in go.vars {
            if name.contains(char::is_whitespace) || value.contains(char::is_whitespace) {
                self.errors.push(format!("-X {name}={value}: no whitespace allowed"));
            }
            let _ = write!(ldflags, " -X {name}={value}");
        }
        let output = self.root(go.install);
        let file = go.install.rsplit('/').next().unwrap_or(go.install).to_owned();
        let mut cmd = self.cmd("go").dir(go.tree).env("GOTOOLCHAIN", "local");
        let mut args = vec!["build"];
        let mut tags = go.tags.to_vec();
        match &go.cgo {
            Cgo::Disabled => cmd = cmd.env("CGO_ENABLED", "0"),
            Cgo::Enabled { libraries } => {
                ldflags.push_str(" -linkmode external -extldflags '-static-pie -flto=thin -Wl,-z,relro,-z,now'");
                args.push("-buildmode=pie");
                // Name and user lookups in Go: a static program has no NSS to load.
                tags.extend(["netgo", "osusergo"]);
                cmd = cmd
                    .env("CGO_ENABLED", "1")
                    .env("CC", "cc")
                    .env("CGO_CFLAGS", "-O2 -flto=thin");
                if let Some(libraries) = libraries {
                    cmd = cmd
                        .env("PKG_CONFIG_PATH", libraries.join("usr/lib/pkgconfig"))
                        .env("PKG_CONFIG_SYSROOT_DIR", libraries);
                }
            }
        }
        cmd.args(args)
            .args(["-mod=vendor", "-trimpath", "-buildvcs=false", "-tags"])
            .arg(tags.join(" "))
            .arg("-ldflags")
            .arg(ldflags)
            .arg("-o")
            .arg(&output)
            .arg(go.package)
            .run();
        let into = self.inventory(Inventory::GoBuildInfo, &file);
        self.cmd("go").args(["version", "-m"]).arg(&output).capture(&into);
    }

    /// Downloads the crates pinned by `Cargo.lock` (fetch phase, with network).
    pub fn cargo_fetch(&mut self) {
        let workspace = self.repository();
        self.cmd("cargo")
            .dir(&workspace)
            .env("CARGO_HTTP_CAINFO", "/etc/ssl/certs/ca-certificates.crt")
            .args(["fetch", "--locked", "--target", RUST_TARGET])
            .run();
    }

    /// Builds workspace binaries offline and records the crates and toolchain for the SBOM.
    pub fn cargo_build(&mut self, binaries: &[CargoBinary]) {
        let workspace = self.repository();
        let target = self.cache("target");
        let selection: Vec<&str> = binaries
            .iter()
            .flat_map(|b| ["-p", b.package, "--bin", b.package])
            .collect();
        self.cmd("cargo")
            .dir(&workspace)
            .env("CARGO_TARGET_DIR", &target)
            .env("RUSTFLAGS", RUST_STATIC)
            .args(["build", "--offline", "--locked", "--release", "--target", RUST_TARGET])
            .args(selection)
            .run();
        for binary in binaries {
            let to = self.root(binary.install);
            let built = target.join(RUST_TARGET).join("release").join(binary.package);
            self.install(&built, &to, Mode::EXECUTABLE);
        }

        let packages: Vec<&str> = binaries.iter().flat_map(|b| ["-p", b.package]).collect();
        let crates = self.inventory(Inventory::CargoTree, "crates");
        self.cmd("cargo")
            .dir(&workspace)
            .args(["tree", "--offline", "--locked", "-e", "normal", "--prefix", "none"])
            .args(["--target", RUST_TARGET, "--format", "{p}|{l}"])
            .args(packages)
            .capture(&crates);
        // The Rust standard library is linked in but absent from Cargo.lock.
        let toolchain = self.inventory(Inventory::RustToolchain, "rust");
        self.cmd("rustc").arg("--version").capture(&toolchain);
        self.step(Step::Strip);
    }

    /// Configures the kernel `tree` (`make` with `args`, e.g. the toolchain) from nothing: every
    /// option is off (`allnoconfig`) but those of `fragment` and what they select. Then checks that
    /// every option of the fragment made it into the final `.config`.
    pub fn kernel_config(&mut self, tree: &Loc, args: &[&str], fragment: &str) {
        let file = self.work("kconfig.fragment");
        self.write(&file, fragment, Mode::FILE);
        self.cmd("make")
            .dir(tree)
            .args(args.iter().copied())
            .arg(Arg::from("KCONFIG_ALLCONFIG=").concat(&file))
            .args(["-s", "allnoconfig"])
            .run();
        self.step(Step::CheckKernelConfig {
            config: tree.join(".config"),
            fragment: fragment.to_owned(),
        });
    }

    /// Where an SBOM inventory of this build is written.
    fn inventory(&self, kind: Inventory, name: &str) -> Loc {
        Loc::new(Base::Sbom).join(&format!("{name}.{}", kind.extension()))
    }

    /// Checks that a step may write to `loc`.
    fn destination(&mut self, loc: &Loc) {
        if !loc.writable() {
            self.errors.push(format!("{loc} is read-only"));
        }
        if let Base::Image(name) = loc.base()
            && !self.images.iter().any(|image| image.name == *name)
        {
            self.errors
                .push(format!("image {name} is not declared with `container_image`"));
        }
    }

    fn step(&mut self, step: Step) {
        self.steps.push(step);
    }
}

/// A command being described; nothing happens until [`Cmd::run`] or [`Cmd::capture`].
#[must_use = "a command does nothing until `run` or `capture` is called"]
pub struct Cmd<'b> {
    build: &'b mut Build,
    command: Command,
}

impl Cmd<'_> {
    pub fn arg(mut self, arg: impl Into<Arg>) -> Self {
        self.command.args.push(arg.into());
        self
    }

    pub fn args<A: Into<Arg>>(mut self, args: impl IntoIterator<Item = A>) -> Self {
        self.command.args.extend(args.into_iter().map(Into::into));
        self
    }

    pub fn dir(mut self, dir: &Loc) -> Self {
        self.command.dir = dir.clone();
        self
    }

    /// Sets an environment variable for this command only.
    pub fn env(mut self, key: &str, value: impl Into<Arg>) -> Self {
        let valid = !key.is_empty()
            && !key.starts_with(|c: char| c.is_ascii_digit())
            && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if !valid {
            self.build
                .errors
                .push(format!("invalid environment variable name {key:?}"));
        }
        self.command.env.push((key.to_owned(), value.into()));
        self
    }

    pub fn run(self) {
        let Self { build, command } = self;
        build.check(&command);
        build.step(Step::Run(command));
    }

    /// Runs the command and writes its standard output to `into`.
    pub fn capture(self, into: &Loc) {
        let Self { build, command } = self;
        build.check(&command);
        build.destination(into);
        build.step(Step::Capture {
            command,
            into: into.clone(),
        });
    }
}

impl Build {
    /// Patterns are only resolved by the steps that take them, never in commands.
    fn check(&mut self, command: &Command) {
        let args = std::iter::once(&command.program)
            .chain(&command.args)
            .chain(command.env.iter().map(|(_, value)| value));
        for loc in args.flat_map(Arg::locs).chain([&command.dir]) {
            if loc.is_pattern() {
                self.errors.push(format!("pattern {loc} in a command"));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn describe(build: impl FnOnce(&mut Build)) -> anyhow::Result<Plan> {
        Plan::describe(
            &crate::name!("test"),
            |_| Ok(()),
            |b| {
                build(b);
                Ok(())
            },
        )
    }

    fn src() -> Source {
        Source {
            url: "https://x/demo-1.0.tar.gz",
            sha256: crate::sha256::Sha256::digest(b""),
        }
    }

    #[test]
    fn misuses_are_reported_together() {
        const OTHER: Output = Output::new(crate::name!("other"), "file");
        let other_unit: Unit = "tools/other".parse().unwrap();
        let undeclared = ContainerImage {
            name: crate::name!("undeclared"),
            entrypoint: "/x",
            user: (0, 0),
        };
        let error = describe(|b| {
            let other = b.output(&OTHER);
            b.write(&other, "x", Mode::FILE);
            let dep = b.input(&other_unit, Some("file"));
            b.write(&dep, "x", Mode::FILE);
            let image = Loc::new(Base::Image(undeclared.name.clone()));
            b.write(&image.join("x"), "x", Mode::FILE);
            let pattern = b.work("*.c");
            b.cmd("gcc").arg(&pattern).run();
            b.cmd("x").env("NOT VALID", "1").run();
            let _ = b.root("relative");
        })
        .unwrap_err()
        .to_string();
        for expected in [
            "other:file is an output of another component",
            "dep(tools/other):outputs/file is read-only",
            "image undeclared is not declared",
            "pattern work:*.c in a command",
            "invalid environment variable",
            "\"relative\" is not an absolute path",
        ] {
            assert!(error.contains(expected), "{expected:?} missing from {error}");
        }
    }

    #[test]
    fn records_sources_inputs_and_images() {
        let libseccomp: Unit = "standard/libseccomp".parse().unwrap();
        let image = ContainerImage {
            name: crate::name!("demo"),
            entrypoint: "/demo",
            user: (1, 1),
        };
        let plan = describe(|b| {
            assert_eq!(
                b.input(&libseccomp, Some("dev")).to_string(),
                "dep(standard/libseccomp):outputs/dev"
            );
            assert_eq!(b.input(&libseccomp, None).to_string(), "dep(standard/libseccomp):root");
            let _ = b.unpack(&src(), "src");
            let _ = b.source(&src());
            let root = b.container_image(&image);
            b.write(&root.join("demo"), "x", Mode::EXECUTABLE);
        })
        .unwrap();
        assert!(plan.inputs().contains(&libseccomp));
        assert_eq!(plan.sources, [src()], "recorded once");
        assert_eq!(plan.images, [image]);
    }

    #[test]
    fn go_flags_follow_the_subcommand() {
        let plan = describe(|b| {
            let tree = b.work("runc");
            b.go_build(GoBuild {
                tree: &tree,
                package: ".",
                install: "/usr/bin/runc",
                cgo: Cgo::Enabled { libraries: None },
                tags: &["seccomp"],
                vars: &[("main.version", "1.5.2")],
            });
        })
        .unwrap();
        let build = plan.build[0].to_string();
        assert!(build.contains("go build -buildmode=pie -mod=vendor"), "{build}");
        assert!(build.contains("-linkmode external"), "{build}");
        assert_eq!(
            plan.build[1].to_string(),
            "capture  go version -m root:/usr/bin/runc → sbom:runc.gomod"
        );
    }

    #[test]
    fn locations_are_checked() {
        let work = Loc::new(Base::Work);
        assert_eq!(work.join("a/b").join("c").to_string(), "work:a/b/c");
        for bad in ["", "/a", "a//b", "a/./b", "../a", "a/.."] {
            assert!(std::panic::catch_unwind(|| work.join(bad)).is_err(), "{bad:?} accepted");
        }
        assert!(work.join("lib/*.so").is_pattern());
        assert!(std::panic::catch_unwind(|| Mode::new(0o4755)).is_err());
    }
}

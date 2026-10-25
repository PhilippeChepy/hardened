//! The usual build systems: each builds a source tree and installs it into a destination
//! (`DESTDIR`): the component's tree, or one of its outputs. Installs use `--prefix=/usr`: trees
//! are copied onto `/` of the environments holding them.

use super::plan::{Arg, Build, Loc};

/// Options of [`Build::configure_make`].
#[derive(Debug)]
pub struct Configure<'a> {
    /// `--prefix`.
    pub prefix: &'a str,
    /// Arguments after `--prefix`, `VAR=value` ones included.
    pub args: &'a [&'a str],
    /// Runs `configure` in the source tree, for packages that cannot build in another directory.
    pub in_tree: bool,
    /// Its environment variables.
    pub env: &'a [(&'a str, &'a str)],
}

impl Build {
    /// `configure --prefix=<prefix>`, `make` and `make install` into `dest`.
    pub fn configure_make(&mut self, src: &Loc, dest: &Loc, options: Configure<'_>) {
        let dir = if options.in_tree {
            src.clone()
        } else {
            let dir = self.work("build");
            self.mkdir(&dir);
            dir
        };
        let mut configure = self
            .cmd(src.join("configure"))
            .dir(&dir)
            .arg(format!("--prefix={}", options.prefix))
            .args(options.args.iter().copied());
        for (key, value) in options.env {
            configure = configure.env(key, *value);
        }
        configure.run();
        self.make(&dir).run();
        self.make_install(&dir, dest, &[]);
    }

    /// `make install` (or `targets`, when not empty) in `dir`, into `dest`.
    pub fn make_install(&mut self, dir: &Loc, dest: &Loc, targets: &[&str]) {
        let targets = if targets.is_empty() { &["install"][..] } else { targets };
        self.cmd("make")
            .dir(dir)
            .args(targets.iter().copied())
            .arg(Arg::from("DESTDIR=").concat(dest))
            .run();
    }

    /// A CMake project with the Makefile generator (not every environment has ninja), installed
    /// into `dest`.
    pub fn cmake_build(&mut self, src: &Loc, dest: &Loc, args: &[&str]) {
        let build = self.work("build");
        self.cmd("cmake")
            .args(["-G", "Unix Makefiles", "-S"])
            .arg(src)
            .arg("-B")
            .arg(&build)
            .args([
                "-DCMAKE_INSTALL_PREFIX=/usr",
                "-DCMAKE_INSTALL_LIBDIR=lib",
                "-DCMAKE_BUILD_TYPE=Release",
            ])
            .args(args.iter().copied())
            .run();
        self.make(&build).run();
        self.make_install(&build, dest, &[]);
    }

    /// A Meson project, installed into `dest`.
    pub fn meson_build(&mut self, src: &Loc, dest: &Loc, args: &[&str]) {
        let build = self.work("build");
        self.cmd("meson")
            .arg("setup")
            .arg(&build)
            .arg(src)
            .args([
                "--prefix=/usr",
                "--libdir=lib",
                "--buildtype=release",
                "--wrap-mode=nodownload",
            ])
            .args(args.iter().copied())
            .run();
        self.cmd("ninja").arg("-C").arg(&build).run();
        self.cmd("meson")
            .args(["install", "--no-rebuild", "-C"])
            .arg(&build)
            .arg("--destdir")
            .arg(dest)
            .run();
    }
}

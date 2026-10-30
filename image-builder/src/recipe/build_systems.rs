//! The usual build systems: each builds a source tree and installs it into a destination
//! (`DESTDIR`): the component's tree, or one of its outputs. Installs use `--prefix=/usr`: trees
//! are copied onto `/` of the environments holding them.

use super::plan::{Arg, Build, Loc};

impl Build {
    /// `configure --prefix=<prefix> <args>` (`VAR=value` ones included) with `env`, in `dir` (a
    /// build directory, or the source tree for packages that cannot build elsewhere), then `make`
    /// and `make install` into `dest`.
    pub fn configure_make(
        &mut self,
        src: &Loc,
        dir: &Loc,
        dest: &Loc,
        prefix: &str,
        args: Vec<String>,
        env: Vec<(String, String)>,
    ) {
        let mut configure = self
            .cmd(src.join("configure"))
            .dir(dir)
            .arg(format!("--prefix={prefix}"))
            .args(args);
        for (key, value) in env {
            configure = configure.env(&key, value);
        }
        configure.run();
        self.make(dir).run();
        self.make_install(dir, dest, ["install"]);
    }

    /// `make <targets>` (e.g. `install`) in `dir`, into `dest`.
    pub fn make_install(
        &mut self,
        dir: &Loc,
        dest: &Loc,
        targets: impl IntoIterator<Item: Into<Arg>>,
    ) {
        self.cmd("make")
            .dir(dir)
            .args(targets)
            .arg(Arg::from("DESTDIR=").concat(dest))
            .run();
    }

    /// A CMake project with the Makefile generator (not every environment has ninja), installed
    /// into `dest`.
    pub fn cmake_build(&mut self, src: &Loc, dest: &Loc, args: Vec<String>) {
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
            .args(args)
            .run();
        self.make(&build).run();
        self.make_install(&build, dest, ["install"]);
    }

    /// A Meson project, installed into `dest`.
    pub fn meson_build(&mut self, src: &Loc, dest: &Loc, args: Vec<String>) {
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
            .args(args)
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

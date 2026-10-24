//! The components of the image: one recipe per `components/<name>/recipe.rs`.

use crate::recipe::Component;

#[path = "../../../components/base-files/recipe.rs"]
mod base_files;
#[path = "../../../components/ca-certificates/recipe.rs"]
mod ca_certificates;
#[path = "../../../components/containerd/recipe.rs"]
mod containerd;
#[path = "../../../components/dust/recipe.rs"]
mod dust;
#[path = "../../../components/gcc-runtime/recipe.rs"]
mod gcc_runtime;
#[path = "../../../components/glibc/recipe.rs"]
mod glibc;
#[path = "../../../components/kernel/recipe.rs"]
pub mod kernel;
#[path = "../../../components/libseccomp/recipe.rs"]
mod libseccomp;
#[path = "../../../components/pause/recipe.rs"]
pub mod pause;
#[path = "../../../components/runc/recipe.rs"]
mod runc;
#[path = "../../../components/systemd-stub/recipe.rs"]
pub mod systemd_stub;

pub static ALL: &[&dyn Component] = &[
    &base_files::BaseFiles,
    &ca_certificates::CaCertificates,
    &containerd::Containerd,
    &dust::Dust,
    &gcc_runtime::GccRuntime,
    &glibc::Glibc,
    &kernel::Kernel,
    &libseccomp::Libseccomp,
    &pause::Pause,
    &runc::Runc,
    &systemd_stub::SystemdStub,
];

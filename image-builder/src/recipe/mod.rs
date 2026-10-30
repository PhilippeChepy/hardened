//! Component recipes: a target's in `specs/targets/<target>/components/`, those several targets
//! build in `specs/components/` ([`declarative`] describes the format).
//!
//! A recipe gives a component's [`Meta`] (for the SBOM), and its build (and fetch phase, for
//! cargo), described through [`Build`]. Recipes never execute anything: the description is a
//! [`Plan`] of steps, which also records what the build uses (sources, other components'
//! outputs) and the container images it fills. The plan is what the cache key hashes; every plan
//! is described, and checked, when recipes load.

mod build_systems;
mod component_name;
mod container_image;
mod declarative;
mod meta;
mod output;
mod plan;
mod recipes;
mod repo_path;
mod source;
mod unit;

pub use component_name::ComponentName;
pub use container_image::ContainerImage;
pub use meta::{ComponentType, Meta, WORKSPACE_VERSION};
pub use output::Output;
pub use plan::{Arg, Base, Build, Cgo, Cmd, Command, Loc, Mode, Piece, Plan, Step};
pub use recipes::{Recipe, Recipes};
pub use repo_path::RepoPath;
pub use source::Source;
pub use unit::Unit;

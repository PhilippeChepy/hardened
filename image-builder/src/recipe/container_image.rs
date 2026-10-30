//! A container image a component produces.

use crate::recipe::ComponentName;

/// A "from scratch" container image a component produces: the files its build installs into it
/// ([`Build::container_image`](crate::recipe::Build::container_image)), archived by image-builder
/// and shipped in the root filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerImage {
    /// The image is `localhost/hardened/<name>:<component version>`.
    pub name: ComponentName,
    /// Absolute path in the image.
    pub entrypoint: String,
    /// `(uid, gid)`.
    pub user: (u32, u32),
}

//! The `--target` of image commands.

/// The target an image command works on.
#[derive(Debug, Clone, clap::Args)]
pub struct TargetArg {
    /// A target of specs/targets/.
    #[arg(long = "target", default_value = "standard")]
    pub id: String,
}

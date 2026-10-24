//! Outputs: what a component produces besides files in the image (a file or a directory).
//!
//! A recipe declares its outputs as constants next to its code (`pub const IMAGE: Output =
//! Output::new(NAME, "bzImage")`). Consumers import them from the producing recipe's module, so a
//! renamed or removed output is a compile error, and using one is the dependency declaration:
//! [`super::Build::input`] records it.

use std::fmt;

use super::ComponentName;

/// An output named `name` of `component`.
#[derive(Clone, PartialEq, Eq)]
pub struct Output {
    component: ComponentName,
    name: &'static str,
}

impl Output {
    /// Panics (a compile error in a const context) unless `name` is a plain file name.
    pub const fn new(component: ComponentName, name: &'static str) -> Self {
        let bytes = name.as_bytes();
        assert!(!bytes.is_empty(), "empty output name");
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            assert!(
                b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-',
                "output names are file names: alphanumerics and '._-'"
            );
            i += 1;
        }
        assert!(bytes[0] != b'.', "output names cannot start with '.'");
        Self { component, name }
    }

    pub fn component(&self) -> &ComponentName {
        &self.component
    }

    /// File (or directory) name under the component's `outputs/`.
    pub fn name(&self) -> &'static str {
        self.name
    }
}

impl fmt::Debug for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.component, self.name)
    }
}

impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_names_are_file_names() {
        for bad in ["", "a/b", "..", ".hidden", "a b"] {
            assert!(
                std::panic::catch_unwind(|| Output::new(crate::name!("x"), bad)).is_err(),
                "{bad:?} accepted"
            );
        }
    }
}

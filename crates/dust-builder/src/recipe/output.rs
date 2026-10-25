//! Outputs: what a component produces besides its tree (a file or a directory), written to
//! `{out:<name>}` and read by others as `{dep:<target>/<component>/<name>}`, or by image assembly.

use std::fmt;

use super::ComponentName;

/// An output named `name` of `component`.
#[derive(Clone, PartialEq, Eq)]
pub struct Output {
    component: ComponentName,
    name: &'static str,
}

impl Output {
    /// Panics (a compile error in a const context) unless `name` [`Output::is_valid`].
    pub const fn new(component: ComponentName, name: &'static str) -> Self {
        assert!(
            Self::is_valid(name),
            "output names are file names: alphanumerics and '._-'"
        );
        Self { component, name }
    }

    /// A plain file name: alphanumerics and `._-`, not starting with `.`.
    pub const fn is_valid(name: &str) -> bool {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes[0] == b'.' {
            return false;
        }
        let mut i = 0;
        while i < bytes.len() {
            let b = bytes[i];
            if !(b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-') {
                return false;
            }
            i += 1;
        }
        true
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
        assert!(Output::is_valid("kernel.release"));
        for bad in ["", "a/b", "..", ".hidden", "a b"] {
            assert!(!Output::is_valid(bad), "{bad:?} accepted");
        }
    }
}

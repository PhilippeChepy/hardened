//! Command-line arguments.

use crate::validated_string;

validated_string!(
    /// An element of a command line, which `execve` takes: without NUL bytes.
    Argument,
    "argument",
    check_argument
);

fn check_argument(text: &str) -> Result<(), &'static str> {
    if text.contains('\0') {
        Err("must not contain NUL bytes")
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_nul_bytes() {
        assert_eq!("-c".parse::<Argument>().unwrap().as_str(), "-c");
        assert!("".parse::<Argument>().is_ok());
        assert!("a\0b".parse::<Argument>().is_err());
    }
}

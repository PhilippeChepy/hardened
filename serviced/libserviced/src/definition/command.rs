//! A command of a service file: `["-/usr/bin/ctr", "tasks", "delete"]`.

use std::iter;

use serde::{Deserialize, Serialize};

use crate::definition::{AbsolutePath, Error};

/// A program and its arguments, written as one list. A program prefixed with `-` may fail: its
/// failure is ignored, and its output stays off the console.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<String>", into = "Vec<String>")]
pub struct Command {
    program: AbsolutePath,
    /// Without NUL bytes, like the program: each is given to `execve` as is.
    args: Vec<String>,
    may_fail: bool,
}

impl Command {
    /// `program` with `args`, whose failure is not ignored.
    ///
    /// # Errors
    ///
    /// When an argument contains a NUL byte.
    pub fn new(
        program: AbsolutePath,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, Error> {
        let args: Vec<String> = args.into_iter().map(Into::into).collect();
        if args.iter().any(|arg| arg.contains('\0')) {
            return Err(Error::Invalid("an argument contains a NUL byte".into()));
        }
        Ok(Self {
            program,
            args,
            may_fail: false,
        })
    }

    /// This command, its failure ignored.
    #[must_use]
    pub fn ignore_failure(self) -> Self {
        Self {
            may_fail: true,
            ..self
        }
    }

    /// The program, without the `-` prefix.
    #[must_use]
    pub fn program(&self) -> &AbsolutePath {
        &self.program
    }

    /// The arguments, after the program.
    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }

    /// Whether its failure is ignored.
    #[must_use]
    pub fn may_fail(&self) -> bool {
        self.may_fail
    }
}

impl TryFrom<Vec<String>> for Command {
    type Error = Error;

    fn try_from(list: Vec<String>) -> Result<Self, Error> {
        let mut list = list.into_iter();
        let first = list
            .next()
            .ok_or_else(|| Error::Invalid("a command without a program".into()))?;
        let (program, may_fail) = match first.strip_prefix('-') {
            Some(program) => (program, true),
            None => (first.as_str(), false),
        };
        let command = Self::new(program.parse()?, list)?;
        Ok(if may_fail {
            command.ignore_failure()
        } else {
            command
        })
    }
}

impl From<Command> for Vec<String> {
    fn from(command: Command) -> Self {
        let program = if command.may_fail {
            format!("-{}", command.program)
        } else {
            command.program.into()
        };
        iter::once(program).chain(command.args).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(list: &[&str]) -> Result<Command, Error> {
        Command::try_from(list.iter().map(|arg| arg.to_string()).collect::<Vec<_>>())
    }

    #[test]
    fn commands() {
        let pre = parse(&["-/usr/bin/ctr", "rm"]).unwrap();
        assert!(pre.may_fail());
        assert_eq!(pre.program().as_str(), "/usr/bin/ctr");
        assert_eq!(pre.args(), ["rm"]);
        assert_eq!(Vec::from(pre), ["-/usr/bin/ctr", "rm"], "serialized back");
        assert!(!parse(&["/usr/bin/ctr"]).unwrap().may_fail());
    }

    #[test]
    fn invalid_commands_are_rejected() {
        for bad in [
            &[][..],
            &["ctr"],
            &["-ctr"],
            &["--/usr/bin/ctr"],
            &["/usr/bin/c\0tr"],
            &["/usr/bin/ctr", "a\0b"],
        ] {
            assert!(parse(bad).is_err(), "{bad:?} accepted");
        }
    }
}

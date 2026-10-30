//! Processes to run in containers, as `hardened.console.v1.Process`.

use controllers_helpers::Argument;
use controllers_helpers::InvalidMessage;
use controllers_helpers::NonEmpty;
use controllers_helpers::invalid_message;
use controllers_helpers::invalid_message::WithinResult;

use crate::TerminalSize;
use crate::console;

/// What to run in a container, with the environment, user and directory of its main process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecProcess {
    /// The program and its arguments.
    pub command: NonEmpty<Argument>,
    /// `None`: on pipes.
    pub terminal: Option<TerminalSize>,
}

impl From<ExecProcess> for console::Process {
    fn from(process: ExecProcess) -> Self {
        Self {
            command: process.command.into_iter().map(String::from).collect(),
            terminal: process.terminal.map(console::TerminalSize::from),
        }
    }
}

impl TryFrom<console::Process> for ExecProcess {
    type Error = InvalidMessage;

    fn try_from(message: console::Process) -> Result<Self, Self::Error> {
        let command =
            invalid_message::convert_each(message.command, "command", Argument::try_from)?;
        Ok(Self {
            command: NonEmpty::from_vec(command)
                .ok_or_else(|| InvalidMessage::new("command", "must not be empty"))?,
            terminal: message
                .terminal
                .map(TerminalSize::try_from)
                .transpose()
                .within("terminal")?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn process(command: &[&str], terminal: Option<(u32, u32)>) -> console::Process {
        console::Process {
            command: command.iter().map(|&argument| argument.into()).collect(),
            terminal: terminal.map(|(rows, columns)| console::TerminalSize { rows, columns }),
        }
    }

    #[test]
    fn round_trips() {
        for message in [
            process(&["sh"], Some((24, 80))),
            process(&["ls", "-l"], None),
        ] {
            let back = console::Process::from(ExecProcess::try_from(message.clone()).unwrap());
            assert_eq!(back, message);
        }
    }

    #[test]
    fn rejects_invalid_processes() {
        let field = |message: console::Process| {
            ExecProcess::try_from(message)
                .unwrap_err()
                .field()
                .to_owned()
        };
        assert_eq!(field(process(&[], None)), "command");
        assert_eq!(field(process(&["a\0b"], None)), "command[0]");
        assert_eq!(field(process(&["sh"], Some((0, 80)))), "terminal.rows");
    }
}

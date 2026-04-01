//! Willow-specific UCAN command hierarchy.
//!
//! ```text
//! willow              ← full access (proves read, write, and enumerate)
//! ├── willow/read     ← read-only access (used in PAI)
//! ├── willow/write    ← write-only access (used in entry authorization)
//! └── willow/enumerate ← namespace membership proof (PAI awkward pairs)
//! ```

use serde::{Deserialize, Serialize};
use ucan::command::Command;

/// Willow-specific UCAN commands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum WillowCommand {
    /// Full access — proves read, write, and enumerate.
    Full,
    /// Read-only access — used in PAI for overlap detection.
    Read,
    /// Write-only access — used in entry authorization tokens.
    Write,
    /// Namespace membership proof — used for PAI awkward pair resolution.
    /// Does NOT grant read or write access to data.
    Enumerate,
}

impl WillowCommand {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Full => "willow",
            Self::Read => "willow/read",
            Self::Write => "willow/write",
            Self::Enumerate => "willow/enumerate",
        }
    }

    pub fn from_ucan_command(cmd: &Command) -> Option<Self> {
        let segments = cmd.segments();
        match segments.as_slice() {
            [w] if w == "willow" => Some(Self::Full),
            [w, r] if w == "willow" && r == "read" => Some(Self::Read),
            [w, r] if w == "willow" && r == "write" => Some(Self::Write),
            [w, r] if w == "willow" && r == "enumerate" => Some(Self::Enumerate),
            _ => None,
        }
    }

    pub fn to_ucan_command(self) -> Command {
        match self {
            Self::Full => Command::new(vec!["willow".to_owned()]),
            Self::Read => Command::new(vec!["willow".to_owned(), "read".to_owned()]),
            Self::Write => Command::new(vec!["willow".to_owned(), "write".to_owned()]),
            Self::Enumerate => {
                Command::new(vec!["willow".to_owned(), "enumerate".to_owned()])
            }
        }
    }

    pub fn proves_read(&self) -> bool {
        matches!(self, Self::Full | Self::Read)
    }

    pub fn proves_write(&self) -> bool {
        matches!(self, Self::Full | Self::Write)
    }

    pub fn proves_enumerate(&self) -> bool {
        matches!(self, Self::Full | Self::Enumerate)
    }

    pub fn access_mode(&self) -> crate::proto::meadowcap::AccessMode {
        use crate::proto::meadowcap::AccessMode;
        match self {
            Self::Full | Self::Write => AccessMode::Write,
            Self::Read | Self::Enumerate => AccessMode::Read,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_commands() {
        for cmd in [
            WillowCommand::Full,
            WillowCommand::Read,
            WillowCommand::Write,
            WillowCommand::Enumerate,
        ] {
            let ucan_cmd = cmd.to_ucan_command();
            let parsed = WillowCommand::from_ucan_command(&ucan_cmd);
            assert_eq!(parsed, Some(cmd));
        }
    }

    #[test]
    fn command_hierarchy() {
        let full = WillowCommand::Full.to_ucan_command();
        let read = WillowCommand::Read.to_ucan_command();
        let write = WillowCommand::Write.to_ucan_command();
        let enumerate = WillowCommand::Enumerate.to_ucan_command();

        assert!(read.starts_with(&full));
        assert!(write.starts_with(&full));
        assert!(enumerate.starts_with(&full));
        assert!(!read.starts_with(&write));
        assert!(!enumerate.starts_with(&read));
    }

    #[test]
    fn proves_access() {
        assert!(WillowCommand::Full.proves_read());
        assert!(WillowCommand::Full.proves_write());
        assert!(WillowCommand::Read.proves_read());
        assert!(!WillowCommand::Read.proves_write());
        assert!(!WillowCommand::Write.proves_read());
        assert!(WillowCommand::Write.proves_write());
        // Enumerate proves neither read nor write, but proves enumerate
        assert!(!WillowCommand::Enumerate.proves_read());
        assert!(!WillowCommand::Enumerate.proves_write());
        assert!(WillowCommand::Enumerate.proves_enumerate());
        assert!(WillowCommand::Full.proves_enumerate());
        assert!(!WillowCommand::Read.proves_enumerate());
        assert!(!WillowCommand::Write.proves_enumerate());
    }
}

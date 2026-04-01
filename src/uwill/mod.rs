//! UWill capability system.
//!
//! Replaces Meadowcap with UCAN delegation chains while preserving
//! Willow's geometric Area semantics for PIO/PAI compatibility.

pub mod area_extract;
pub mod chain;
pub mod command;
#[cfg(test)]
mod tests;
pub mod invocation;
pub mod revocation;

pub use chain::{UWillChain, UWillChainRaw};
pub use command::WillowCommand;
pub use invocation::UWillInvocation;

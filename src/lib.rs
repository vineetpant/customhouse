//! Bulkhead — deterministic reference monitor for the MCP tool boundary.
//!
//! Hard constraint (see CLAUDE.md / DESIGN-v2.md): no LLM/model call and no
//! network access exists anywhere in the enforcement path. Policy evaluation
//! is a pure function.

pub mod config;
pub mod invariant;
pub mod ledger;
pub mod proxy;
pub mod upstream;

pub use config::Config;
pub use invariant::{Assessment, Decision, Invariants};
pub use ledger::Ledger;
pub use proxy::{serve_stdio, BulkheadProxy};

/// The crate version, sourced from `Cargo.toml` at compile time.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// The product name, sourced from `Cargo.toml` at compile time.
pub fn name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_matches_cargo_manifest() {
        assert_eq!(version(), env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn name_is_bulkhead() {
        assert_eq!(name(), "bulkhead");
    }
}

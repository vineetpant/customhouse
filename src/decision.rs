//! The decision vocabulary produced by the policy gate and consumed by the
//! ledger (and, in Phase 1, the tiered policy engine).
//!
//! A leaf module: keeping these shared types here means `invariant` (which
//! produces them), `ledger` (which records them), and `proxy` (which acts on
//! them) all depend on a common leaf rather than on each other.

use std::path::PathBuf;

/// The outcome of the pre-forward gate.
///
/// Client-facing by design: `reason` can end up in an MCP error the model reads,
/// so this type deliberately carries no resolved filesystem path.
///
/// Deliberately exhaustive (no `#[non_exhaustive]`): when Phase 1 adds
/// `Escalate`, the compiler must flag every match site that needs to handle it,
/// rather than letting a pre-existing wildcard arm silently treat it as allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny { reason: String },
}

/// The full, operator-side result of one evaluation: the client-facing
/// `Decision` plus the matched protected path on a deny. `matched_path` is read
/// only by the ledger/operator side and never crosses the client boundary — the
/// client path projects down to `decision`.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub decision: Decision,
    pub matched_path: Option<PathBuf>,
}

impl Assessment {
    /// An allow with no matched path.
    pub fn allow() -> Self {
        Self {
            decision: Decision::Allow,
            matched_path: None,
        }
    }
}

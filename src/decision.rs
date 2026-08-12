//! The decision vocabulary produced by the enforcement layers and consumed by
//! the ledger and the proxy.
//!
//! A leaf module: keeping these shared types here means `invariant` and `flow`
//! (which produce them), `ledger` (which records them), and `proxy` (which acts
//! on them) all depend on a common leaf rather than on each other.
//!
//! ## Two decision types, deliberately
//!
//! There are two outcome types, not one, because the two enforcement layers do
//! not have the same authority:
//!
//! - [`InvariantOutcome`] — what the compiled-in §3 self-protection invariants
//!   return. It has **no escalation variant**, so an invariant *cannot* ask an
//!   operator for permission. An approvable invariant is not an invariant, and a
//!   compromised session must not be able to nag its way past self-protection.
//!   This is enforced by the type, not by a rule someone has to remember.
//! - [`Decision`] — the full flow-policy vocabulary, which may escalate.
//!
//! An `InvariantOutcome` widens into a `Decision` (via `From`), never the
//! reverse.

use std::path::PathBuf;

/// The outcome of the compiled-in self-protection invariants (§3).
///
/// Allow or Deny only, by construction. See the module docs for why escalation
/// is deliberately unrepresentable here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvariantOutcome {
    Allow,
    Deny { reason: String },
}

/// The outcome of flow policy — the full vocabulary the proxy acts on.
///
/// Client-facing by design: every `reason` here can end up in an MCP error the
/// model reads, so no variant carries a resolved filesystem path or any
/// content drawn from an untrusted result (§7.6).
///
/// Deliberately exhaustive (no `#[non_exhaustive]`): a new outcome must break
/// every match site so each one is revisited, rather than silently falling
/// through a wildcard into "allow".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny {
        reason: String,
    },
    /// Refused pending an out-of-band operator approval. The call is *not*
    /// held: the client is told what to approve and may retry once an operator
    /// has acked it. Holding the call would need a queue, timeouts and
    /// cancellation plumbing for no security gain.
    Escalate {
        reason: String,
    },
}

impl From<InvariantOutcome> for Decision {
    fn from(outcome: InvariantOutcome) -> Self {
        match outcome {
            InvariantOutcome::Allow => Decision::Allow,
            InvariantOutcome::Deny { reason } => Decision::Deny { reason },
        }
    }
}

impl Decision {
    /// Whether the call may proceed to its upstream.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// The full, operator-side result of evaluating the §3 invariants: the
/// client-facing outcome plus the matched protected path on a deny.
///
/// `matched_path` is read only by the ledger/operator side and never crosses the
/// client boundary — the client path projects down to `outcome`.
#[derive(Debug, Clone)]
pub struct Assessment {
    pub outcome: InvariantOutcome,
    pub matched_path: Option<PathBuf>,
}

impl Assessment {
    /// An allow with no matched path.
    pub fn allow() -> Self {
        Self {
            outcome: InvariantOutcome::Allow,
            matched_path: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariant_outcomes_widen_into_decisions() {
        assert_eq!(Decision::from(InvariantOutcome::Allow), Decision::Allow);
        assert_eq!(
            Decision::from(InvariantOutcome::Deny {
                reason: "blocked".into()
            }),
            Decision::Deny {
                reason: "blocked".into()
            }
        );
    }

    #[test]
    fn only_allow_lets_a_call_proceed() {
        assert!(Decision::Allow.is_allowed());
        assert!(!Decision::Deny { reason: "x".into() }.is_allowed());
        assert!(!Decision::Escalate { reason: "x".into() }.is_allowed());
    }

    // There is deliberately no test that an invariant escalates, because there
    // is no way to write one: `InvariantOutcome` has no such variant. That is
    // the guarantee — enforced by the compiler rather than by a passing test.
}

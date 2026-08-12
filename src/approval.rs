//! Out-of-band operator approvals for escalated sink calls (DESIGN-v2.md §10).
//!
//! A leaf module — a small persistent store, no policy. `flow` decides that a
//! call needs approval; this records whether an operator gave one.
//!
//! ## Deliberately minimal
//!
//! An approval is granted by running `penstock approve <sink-class>` in a
//! terminal, which writes to `<penstock-home>/approvals.json`. The blocked call
//! is **not** held open waiting for it: the client is refused and told what to
//! approve, and may retry. Holding the call would require a pending-request
//! queue, cancellation handling and client-timeout coordination for no security
//! benefit — the operator's decision is the same either way.
//!
//! Two properties keep a granted approval from becoming a standing hole:
//!
//! - **Single use.** Consuming an approval removes it, so one ack authorises one
//!   retry rather than the rest of the session.
//! - **Expiry.** An unused approval goes stale after [`VALIDITY`], so walking
//!   away from a terminal does not leave a sink permanently open.
//!
//! The store lives inside the Penstock home directory, so the §3 invariants
//! already prevent a mediated call from granting its own approval — the agent
//! cannot write the file that would unblock it. That is asserted by a test below.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::paths::penstock_home;
use crate::sink::SinkClass;

const APPROVAL_FILE: &str = "approvals.json";

/// How long an unused approval stays valid. Short on purpose: this is the
/// "timeout to deny" that keeps an abandoned ack from lingering.
pub const VALIDITY_MS: u64 = 10 * 60 * 1000;

/// What happened when a call tried to spend an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// An operator had approved this class; the approval is now spent.
    Granted,
    /// An approval existed but had gone stale, and has been discarded.
    Expired,
    /// No operator approval was waiting.
    Missing,
}

/// Failures reading or writing the approval store.
#[derive(Debug, thiserror::Error)]
pub enum ApprovalError {
    #[error("failed to read approval store: {0}")]
    Read(#[source] std::io::Error),
    #[error("failed to parse approval store: {0}")]
    Parse(#[source] serde_json::Error),
    #[error("failed to write approval store: {0}")]
    Write(#[source] std::io::Error),
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct ApprovalData {
    /// Sink class identifier to the epoch-millis it was granted.
    #[serde(default)]
    granted: BTreeMap<String, u64>,
}

/// The persistent set of operator approvals awaiting use.
pub struct ApprovalStore {
    path: PathBuf,
    data: ApprovalData,
}

impl ApprovalStore {
    /// Open the store at `<penstock-home>/approvals.json`.
    pub fn open() -> Self {
        Self::open_in(&penstock_home())
    }

    /// Open under an explicit home directory (tests supply a tempdir).
    /// An unreadable store starts empty — failing closed, since an empty store
    /// approves nothing.
    pub fn open_in(home: &Path) -> Self {
        let path = home.join(APPROVAL_FILE);
        let data = Self::load(&path).unwrap_or_else(|e| {
            eprintln!("penstock: approval store unreadable, treating as empty: {e}");
            ApprovalData::default()
        });
        Self { path, data }
    }

    fn load(path: &Path) -> Result<ApprovalData, ApprovalError> {
        match std::fs::read_to_string(path) {
            Ok(text) => serde_json::from_str(&text).map_err(ApprovalError::Parse),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(ApprovalData::default()),
            Err(e) => Err(ApprovalError::Read(e)),
        }
    }

    /// The resolved store path (used by the §3 protection test).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record an operator approval for one retry of a sink class.
    pub fn grant(&mut self, class: SinkClass, now_ms: u64) {
        self.data.granted.insert(class.as_str().to_string(), now_ms);
    }

    /// Spend an approval, if a valid one is waiting. Single use: a successful
    /// consume removes it, and an expired one is discarded rather than honoured.
    pub fn consume(&mut self, class: SinkClass, now_ms: u64) -> ApprovalOutcome {
        let Some(granted_at) = self.data.granted.remove(class.as_str()) else {
            return ApprovalOutcome::Missing;
        };
        if now_ms.saturating_sub(granted_at) > VALIDITY_MS {
            ApprovalOutcome::Expired
        } else {
            ApprovalOutcome::Granted
        }
    }

    /// Persist the store, creating the home directory if needed.
    pub fn save(&self) -> Result<(), ApprovalError> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(ApprovalError::Write)?;
        }
        let json = serde_json::to_string_pretty(&self.data).map_err(ApprovalError::Parse)?;
        std::fs::write(&self.path, json).map_err(ApprovalError::Write)
    }
}

/// Epoch millis, for granting and expiry checks.
pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant::Invariants;

    #[test]
    fn an_approval_can_be_spent_once() {
        let home = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::open_in(home.path());
        let now = 1_000_000;

        store.grant(SinkClass::ExternalSend, now);
        assert_eq!(
            store.consume(SinkClass::ExternalSend, now + 1),
            ApprovalOutcome::Granted
        );
        assert_eq!(
            store.consume(SinkClass::ExternalSend, now + 2),
            ApprovalOutcome::Missing,
            "one ack authorises one retry, not the rest of the session"
        );
    }

    #[test]
    fn approvals_are_scoped_to_their_class() {
        let home = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::open_in(home.path());
        store.grant(SinkClass::ExternalSend, 0);
        assert_eq!(
            store.consume(SinkClass::PaymentTransfer, 1),
            ApprovalOutcome::Missing,
            "approving an email must never authorise a payment"
        );
    }

    #[test]
    fn a_stale_approval_is_not_honoured() {
        let home = tempfile::tempdir().unwrap();
        let mut store = ApprovalStore::open_in(home.path());
        store.grant(SinkClass::DataEgress, 0);
        assert_eq!(
            store.consume(SinkClass::DataEgress, VALIDITY_MS + 1),
            ApprovalOutcome::Expired
        );
        assert_eq!(
            store.consume(SinkClass::DataEgress, VALIDITY_MS + 2),
            ApprovalOutcome::Missing,
            "an expired approval is discarded, not left to be retried"
        );
    }

    #[test]
    fn approvals_survive_a_restart() {
        // The CLI grants in one process; the proxy spends it in another.
        let home = tempfile::tempdir().unwrap();
        {
            let mut store = ApprovalStore::open_in(home.path());
            store.grant(SinkClass::ExternalSend, 5_000);
            store.save().unwrap();
        }
        let mut store = ApprovalStore::open_in(home.path());
        assert_eq!(
            store.consume(SinkClass::ExternalSend, 6_000),
            ApprovalOutcome::Granted
        );
    }

    #[test]
    fn a_mediated_call_cannot_grant_its_own_approval() {
        // The store lives inside the protected home, so §3 denies any tool call
        // that tries to write it. Without this, a compromised session could
        // approve its own exfiltration.
        let home = tempfile::tempdir().unwrap();
        let store = ApprovalStore::open_in(home.path());
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);

        let mut args = serde_json::Map::new();
        args.insert(
            "path".into(),
            serde_json::Value::String(store.path().to_str().unwrap().into()),
        );
        let write_the_store =
            rmcp::model::CallToolRequestParams::new("fs__write_file").with_arguments(args);

        assert!(
            matches!(
                invariants.evaluate(&write_the_store),
                crate::decision::InvariantOutcome::Deny { .. }
            ),
            "an agent must not be able to write the file that unblocks it"
        );
    }
}

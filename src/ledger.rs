//! The append-only ledger (DESIGN-v2.md §3-I5).
//!
//! Every mediated `tools/call` is recorded here — allowed and denied alike —
//! from the single chokepoint in `proxy::call_tool`. The ledger lives at
//! `<customhouse-home>/ledger.jsonl`, inside the directory the §3 invariant gate
//! already protects, so a mediated call cannot be steered into reading or
//! truncating it (I-5 holds for free; the drift-catching test is below).
//!
//! Writer discipline: the file is opened in append mode and never rewritten.
//!
//! Phase 0 scope: entries carry only what a passthrough proxy actually knows —
//! id, timestamp, tool, resolved server, decision, and (on deny) the matched
//! path as operator detail. Session, taint labels, rule ids, arg shapes/digests,
//! and latency are Phase 1; they are left out, not stubbed.
//!
//! The JSONL entry schema is a contract for offline consumers (Phase 3 footprint
//! diffing reads these files): evolve it additively — add new optional fields,
//! never rename or repurpose existing ones.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::model::CallToolRequestParams;
use serde::{Deserialize, Serialize};

use crate::decision::{Assessment, Decision, InvariantOutcome};
use crate::flow::FlowAssessment;
use crate::paths::customhouse_home;
use crate::pin::PinOutcome;
use crate::session::TaintSource;

const LEDGER_FILE: &str = "ledger.jsonl";

/// An append-only JSONL sink for mediated-call records.
pub struct Ledger {
    path: PathBuf,
    /// `None` means the ledger is disabled (the file could not be opened). In
    /// Phase 0 that is not fatal — see `record` for the fail-open posture.
    sink: Mutex<Option<File>>,
    next_id: AtomicU64,
}

impl Ledger {
    /// Open the ledger at `<customhouse-home>/ledger.jsonl` (production).
    pub fn open() -> Self {
        Self::open_in(&customhouse_home())
    }

    /// Open the ledger under an explicit home directory (tests supply a tempdir).
    pub fn open_in(home: &Path) -> Self {
        let path = home.join(LEDGER_FILE);
        let sink = match Self::try_open(home, &path) {
            Ok(file) => Some(file),
            Err(e) => {
                eprintln!(
                    "customhouse: ledger disabled — cannot open {}: {e}",
                    path.display()
                );
                None
            }
        };
        Self {
            path,
            sink: Mutex::new(sink),
            next_id: AtomicU64::new(0),
        }
    }

    /// A ledger that records nothing (used by proxies built without upstreams).
    pub fn disabled() -> Self {
        Self {
            path: PathBuf::new(),
            sink: Mutex::new(None),
            next_id: AtomicU64::new(0),
        }
    }

    fn try_open(home: &Path, path: &Path) -> std::io::Result<File> {
        fs::create_dir_all(home)?;
        OpenOptions::new().create(true).append(true).open(path)
    }

    /// The resolved ledger file path (used by the I-5 test).
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Record one mediated call and its assessment. `server` is the owning
    /// upstream, supplied structurally by the caller (via `Registry::server_of`)
    /// rather than re-parsed from the tool name. The deny detail is the matched
    /// protected path — operator-only, and safe here precisely because the ledger
    /// is unreadable through the mediated surface (I-5).
    /// Returns the ledger id assigned to this record, so a later taint event
    /// can cite the exact call that caused it.
    pub fn record_call(
        &self,
        request: &CallToolRequestParams,
        server: Option<&str>,
        assessment: &Assessment,
    ) -> u64 {
        let (decision, detail) = match &assessment.outcome {
            InvariantOutcome::Allow => (LedgerDecision::Allow, None),
            InvariantOutcome::Deny { .. } => (
                LedgerDecision::Deny,
                assessment
                    .matched_path
                    .as_ref()
                    .map(|p| p.display().to_string()),
            ),
        };

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = CallEntry {
            kind: EntryKind::Call,
            id,
            ts_ms: now_ms(),
            tool: request.name.to_string(),
            server: server.map(str::to_string),
            decision,
            detail,
        };
        self.write(&entry);
        id
    }

    /// Record that an untrusted upstream's result entered the session.
    ///
    /// This is the provenance root every later flow denial points back to, so
    /// it must be written before the result is handed to the client.
    pub fn record_taint(&self, source: &TaintSource) {
        self.write(&TaintEntry {
            kind: EntryKind::Taint,
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts_ms: now_ms(),
            server: source.server.clone(),
            tool: source.tool.clone(),
            caused_by_call: source.call_id,
        });
    }

    /// Record a flow-rule outcome for a sink call: blocked, escalated, or
    /// allowed-because-clean. Carries the full provenance chain.
    pub fn record_flow(&self, tool: &str, assessment: &FlowAssessment) {
        let Some(class) = assessment.sink_class else {
            return; // not a sink; the call record already covers it
        };
        let outcome = match assessment.decision {
            // An allow granted by the destination rule is a distinct outcome, not
            // an ordinary allow: it is the compensating control for the residual
            // channel in §17.6, and the operator must be able to find every use
            // of it. Because `record_flow` runs before the decision is acted on,
            // the exemption cannot be granted without this line executing.
            Decision::Allow if assessment.exemption.is_some() => FlowOutcome::AllowedByAuthorMatch,
            Decision::Allow => FlowOutcome::Allowed,
            Decision::Deny { .. } => FlowOutcome::Blocked,
            Decision::Escalate { .. } => FlowOutcome::Escalated,
        };
        self.write(&FlowEntry {
            kind: EntryKind::Flow,
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts_ms: now_ms(),
            tool: tool.to_string(),
            sink_class: class.as_str(),
            outcome,
            tainted_by: assessment
                .taint_sources
                .iter()
                .map(|s| format!("{}:{}", s.server, s.call_id))
                .collect(),
            matched_author: assessment.exemption.as_ref().map(|e| e.author.clone()),
            agreeing_sources: assessment
                .exemption
                .as_ref()
                .map(|e| {
                    e.agreeing_sources
                        .iter()
                        .map(|s| format!("{}:{}", s.server, s.call_id))
                        .collect()
                })
                .unwrap_or_default(),
        });
    }

    /// Record an operator's answer to an escalation — the other half of the
    /// evidence pair that makes an approval auditable.
    pub fn record_approval(&self, sink_class: &str, granted: bool) {
        self.write(&ApprovalEntry {
            kind: EntryKind::Approval,
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts_ms: now_ms(),
            sink_class: sink_class.to_string(),
            granted,
        });
    }

    /// Record a metadata-pinning event: a tool pinned at first sight, or a tool
    /// withheld because its definition or its server's version changed. Like call
    /// records this is operator-only, so it may carry the untrusted before/after
    /// definition diff — the ledger is unreadable via the mediated surface (I-5).
    /// Unchanged tools produce no record.
    pub fn record_metadata(&self, server: &str, tool: &str, outcome: &PinOutcome) {
        let (event, reason, detail) = match outcome {
            PinOutcome::FirstSight => (MetadataOutcome::Pinned, None, None),
            PinOutcome::Unchanged => return,
            PinOutcome::Mutated { pinned, current } => (
                MetadataOutcome::Withheld,
                Some("definition_changed"),
                Some(format!("pinned={pinned} current={current}")),
            ),
            PinOutcome::VersionChanged {
                pinned_version,
                current_version,
            } => (
                MetadataOutcome::Withheld,
                Some("version_changed"),
                Some(format!("{pinned_version:?} -> {current_version:?}")),
            ),
        };

        let entry = MetadataEntry {
            kind: EntryKind::Metadata,
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts_ms: now_ms(),
            server: server.to_string(),
            tool: tool.to_string(),
            event,
            reason,
            detail,
        };
        self.write(&entry);
    }

    fn write(&self, entry: &impl Serialize) {
        // Phase 0 posture: a logging failure must NOT block the mediated call.
        // Here the ledger is an observability record, not the enforcement record.
        // This flips to fail-closed in Phase 1, once an approval writes a
        // declassification record that must be durable to be trusted.
        let mut guard = self.sink.lock().unwrap_or_else(|e| e.into_inner());
        let Some(file) = guard.as_mut() else {
            return;
        };
        let mut line = match serde_json::to_string(entry) {
            Ok(line) => line,
            Err(e) => {
                eprintln!("customhouse: ledger serialize failed (call still proceeds): {e}");
                return;
            }
        };
        line.push('\n');
        if let Err(e) = file.write_all(line.as_bytes()) {
            eprintln!("customhouse: ledger write failed (call still proceeds): {e}");
        }
    }
}

/// Which kind of event a ledger line records. Written on every entry; a line
/// from before this discriminator existed has no `kind` and deserializes as
/// `Call` (see the round-trip test), so old ledgers stay readable.
#[derive(Serialize, Deserialize, Debug, Default, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum EntryKind {
    #[default]
    Call,
    Metadata,
    /// Untrusted content entered the session.
    Taint,
    /// A sink call was evaluated against session taint.
    Flow,
    /// An operator answered an escalation.
    Approval,
}

/// A mediated `tools/call` and its decision.
#[derive(Serialize)]
struct CallEntry {
    kind: EntryKind,
    /// Monotonic within a single process run only; NOT stable across restarts.
    id: u64,
    ts_ms: u64,
    tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    decision: LedgerDecision,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// The decision as recorded in the ledger. Serializes to `"allow"` / `"deny"`.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum LedgerDecision {
    Allow,
    Deny,
}

/// A metadata-pinning event: a tool pinned or withheld.
#[derive(Serialize)]
struct MetadataEntry {
    kind: EntryKind,
    id: u64,
    ts_ms: u64,
    server: String,
    tool: String,
    event: MetadataOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// Untrusted content entering the session.
#[derive(Serialize)]
struct TaintEntry {
    kind: EntryKind,
    id: u64,
    ts_ms: u64,
    server: String,
    tool: String,
    /// Ledger id of the call whose result carried the untrusted content.
    caused_by_call: u64,
}

/// A sink call weighed against session taint.
#[derive(Serialize)]
struct FlowEntry {
    kind: EntryKind,
    id: u64,
    ts_ms: u64,
    tool: String,
    sink_class: &'static str,
    outcome: FlowOutcome,
    /// `server:call_id` for every taint source cited.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    tainted_by: Vec<String>,
    /// The author every recipient matched, when the destination rule allowed
    /// the call (§17.5).
    #[serde(skip_serializing_if = "Option::is_none")]
    matched_author: Option<String>,
    /// The full set of taint sources that agreed on that author, recorded whole
    /// so a later per-source refinement can reconstruct this decision.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    agreeing_sources: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum FlowOutcome {
    Allowed,
    /// Allowed only because every recipient was the author of the tainted
    /// content. Distinct from `Allowed` so uses of the exemption are findable.
    AllowedByAuthorMatch,
    Blocked,
    Escalated,
}

/// An operator's answer to an escalation.
#[derive(Serialize)]
struct ApprovalEntry {
    kind: EntryKind,
    id: u64,
    ts_ms: u64,
    sink_class: String,
    granted: bool,
}

/// Serializes to `"pinned"` / `"withheld"`.
#[derive(Serialize)]
#[serde(rename_all = "lowercase")]
enum MetadataOutcome {
    Pinned,
    Withheld,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::invariant::Invariants;
    use serde_json::Value;
    use std::path::PathBuf;

    fn call(tool: &str, path_arg: Option<&str>) -> CallToolRequestParams {
        match path_arg {
            Some(p) => {
                let mut args = serde_json::Map::new();
                args.insert("path".into(), Value::String(p.into()));
                CallToolRequestParams::new(tool.to_string()).with_arguments(args)
            }
            None => CallToolRequestParams::new(tool.to_string()),
        }
    }

    fn allow() -> Assessment {
        Assessment {
            outcome: InvariantOutcome::Allow,
            matched_path: None,
        }
    }

    fn deny(path: &str) -> Assessment {
        Assessment {
            outcome: InvariantOutcome::Deny {
                reason: "denied".into(),
            },
            matched_path: Some(PathBuf::from(path)),
        }
    }

    fn read_entries(path: &Path) -> Vec<Value> {
        fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }

    #[test]
    fn records_allow_and_deny_with_expected_fields() {
        let home = tempfile::tempdir().unwrap();
        let ledger = Ledger::open_in(home.path());
        ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        ledger.record_call(
            &call("fs__write", Some("/etc/x")),
            Some("fs"),
            &deny("/home/u/.customhouse/secret"),
        );

        let entries = read_entries(ledger.path());
        assert_eq!(entries.len(), 2);

        assert_eq!(entries[0]["kind"], "call");
        assert_eq!(entries[0]["tool"], "web__fetch");
        assert_eq!(entries[0]["server"], "web");
        assert_eq!(entries[0]["decision"], "allow");
        assert!(
            entries[0].get("detail").is_none(),
            "allow carries no detail"
        );
        assert_eq!(entries[0]["id"], 0);

        assert_eq!(entries[1]["decision"], "deny");
        assert_eq!(entries[1]["server"], "fs");
        assert_eq!(entries[1]["detail"], "/home/u/.customhouse/secret");
        assert_eq!(entries[1]["id"], 1);
    }

    #[test]
    fn reopening_appends_rather_than_truncating() {
        let home = tempfile::tempdir().unwrap();
        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        }
        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        }
        assert_eq!(read_entries(&home.path().join(LEDGER_FILE)).len(), 2);
    }

    #[test]
    fn ledger_path_resolves_under_a_protected_root() {
        // I-5: the invariant gate protects the home dir, so the ledger inside it
        // is unreadable via a mediated call. This test fails if the ledger's
        // location ever drifts out from under the protected home root.
        let home = tempfile::tempdir().unwrap();
        let ledger = Ledger::open_in(home.path());
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);

        let target = ledger.path().to_str().unwrap();
        let read_the_ledger = call("fs__read", Some(target));
        assert!(
            matches!(
                invariants.evaluate(&read_the_ledger),
                InvariantOutcome::Deny { .. }
            ),
            "a mediated read of the ledger path must be denied (I-5)"
        );
    }

    #[test]
    fn fail_open_when_the_file_cannot_be_opened() {
        // Use a regular file as the "home", so create_dir_all fails: the ledger
        // must degrade to disabled and record without panicking or blocking.
        let dir = tempfile::tempdir().unwrap();
        let not_a_dir = dir.path().join("iam_a_file");
        fs::write(&not_a_dir, b"x").unwrap();

        let ledger = Ledger::open_in(&not_a_dir);
        ledger.record_call(&call("web__fetch", None), Some("web"), &allow()); // must not panic
    }

    #[test]
    fn records_pin_and_withhold_metadata_events() {
        let home = tempfile::tempdir().unwrap();
        let ledger = Ledger::open_in(home.path());
        ledger.record_metadata("mock", "mock__echo", &PinOutcome::FirstSight);
        ledger.record_metadata(
            "mock",
            "mock__echo",
            &PinOutcome::Mutated {
                pinned: "old".into(),
                current: "new".into(),
            },
        );
        // Unchanged produces no record.
        ledger.record_metadata("mock", "mock__echo", &PinOutcome::Unchanged);

        let entries = read_entries(ledger.path());
        assert_eq!(entries.len(), 2, "unchanged must not be recorded");

        assert_eq!(entries[0]["kind"], "metadata");
        assert_eq!(entries[0]["tool"], "mock__echo");
        assert_eq!(entries[0]["event"], "pinned");
        assert!(entries[0].get("reason").is_none());

        assert_eq!(entries[1]["kind"], "metadata");
        assert_eq!(entries[1]["event"], "withheld");
        assert_eq!(entries[1]["reason"], "definition_changed");
        assert!(entries[1]["detail"]
            .as_str()
            .unwrap()
            .contains("pinned=old"));
    }

    #[test]
    fn an_exemption_cannot_be_granted_without_leaving_evidence() {
        // The compensating control for DESIGN-v2.md §17.6. `record_flow` runs
        // before the decision is acted on, so if this event were ever absent the
        // exemption would be silent — which is indistinguishable from having no
        // enforcement at all.
        use crate::flow::{Exemption, FlowAssessment};
        use crate::session::TaintSource;

        let home = tempfile::tempdir().unwrap();
        let ledger = Ledger::open_in(home.path());

        let source = TaintSource {
            server: "desk".into(),
            tool: "desk__read_ticket".into(),
            call_id: 3,
            author: Some("customer@example.com".into()),
        };
        let assessment = FlowAssessment {
            decision: Decision::Allow,
            sink_class: Some(crate::sink::SinkClass::ExternalSend),
            taint_sources: vec![source.clone()],
            exemption: Some(Exemption {
                author: "customer@example.com".into(),
                agreeing_sources: vec![source],
            }),
        };
        ledger.record_flow("mail__send_email", &assessment);

        let entries = read_entries(ledger.path());
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0]["outcome"], "allowedbyauthormatch",
            "an author-match allow must be distinguishable from an ordinary allow"
        );
        assert_eq!(entries[0]["matched_author"], "customer@example.com");
        assert_eq!(
            entries[0]["agreeing_sources"][0], "desk:3",
            "the whole agreeing set is recorded for later refinement"
        );
    }

    #[test]
    fn old_entry_without_kind_parses_as_call() {
        // A ledger line written before the `kind` discriminator existed has no
        // `kind` field; a reader must treat it as a call, not fail.
        #[derive(Deserialize)]
        struct Header {
            #[serde(default)]
            kind: EntryKind,
        }
        let old = r#"{"id":0,"ts_ms":1,"tool":"web__fetch","server":"web","decision":"allow"}"#;
        let header: Header = serde_json::from_str(old).unwrap();
        assert_eq!(header.kind, EntryKind::Call);
    }
}

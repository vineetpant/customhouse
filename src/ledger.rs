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
use sha2::{Digest, Sha256};

use crate::decision::{Assessment, Decision, InvariantOutcome};
use crate::flow::FlowAssessment;
use crate::paths::customhouse_home;
use crate::pin::PinOutcome;
use crate::session::TaintSource;

const LEDGER_FILE: &str = "ledger.jsonl";

/// The `prev_hash` of the first entry in a chain. A fixed, documented value
/// rather than an absent field, so "this is the genesis entry" and "this entry
/// lost its chaining" are distinguishable.
pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Hex SHA-256 of a written ledger line, excluding its trailing newline.
fn hash_line(line: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(line.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// What an existing ledger file tells a fresh process about resuming it.
struct Resume {
    /// Hash of the last non-empty line, or genesis for a new or unreadable file.
    prev_hash: String,
    /// One past the highest id already recorded, so ids stay unique per file.
    next_id: u64,
    /// The file does not end in a newline, so the previous run was cut off
    /// mid-record and the next append must start a fresh line.
    needs_newline: bool,
}

/// Open file plus the hash of the last line written.
///
/// These live behind one lock because they must move together: writing a line
/// and advancing the chain head is a single operation, and interleaving them
/// would produce a chain that does not verify.
struct LedgerState {
    file: Option<File>,
    prev_hash: String,
}

/// An append-only JSONL sink for mediated-call records.
pub struct Ledger {
    path: PathBuf,
    /// Sink plus chain head. `file: None` means the ledger is disabled (it could
    /// not be opened), which is not fatal — see `write` for the fail-open posture.
    state: Mutex<LedgerState>,
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
        // Resume the chain before appending. Starting a fresh chain on top of an
        // existing file would leave a break at the join that verification would
        // report forever, indistinguishable from tampering.
        let resumed = Self::resume_from(&path);
        let file = match Self::try_open(home, &path) {
            Ok(mut file) => {
                if resumed.needs_newline {
                    // The previous run died mid-write, leaving a record with no
                    // terminating newline. Appending straight onto it would
                    // concatenate the next record into the fragment and lose
                    // both. Close the line first; the fragment stays in the file
                    // as the evidence that something was cut short.
                    if let Err(e) = file.write_all(b"\n") {
                        eprintln!("customhouse: could not terminate a truncated ledger line: {e}");
                    }
                }
                Some(file)
            }
            Err(e) => {
                eprintln!(
                    "customhouse: ledger disabled, cannot open {}: {e}",
                    path.display()
                );
                None
            }
        };
        Self {
            path,
            state: Mutex::new(LedgerState {
                file,
                prev_hash: resumed.prev_hash,
            }),
            next_id: AtomicU64::new(resumed.next_id),
        }
    }

    /// A ledger that records nothing (used by proxies built without upstreams).
    pub fn disabled() -> Self {
        Self {
            path: PathBuf::new(),
            state: Mutex::new(LedgerState {
                file: None,
                prev_hash: GENESIS_HASH.to_string(),
            }),
            next_id: AtomicU64::new(0),
        }
    }

    /// Everything an existing ledger file dictates about how to append to it.
    ///
    /// One scan, because all three answers come from the same bytes and letting
    /// them disagree is how a resumed ledger corrupts itself.
    fn resume_from(path: &Path) -> Resume {
        let Ok(text) = std::fs::read_to_string(path) else {
            return Resume {
                prev_hash: GENESIS_HASH.to_string(),
                next_id: 0,
                needs_newline: false,
            };
        };
        Resume {
            prev_hash: text
                .lines()
                .rfind(|l| !l.trim().is_empty())
                .map(hash_line)
                .unwrap_or_else(|| GENESIS_HASH.to_string()),
            // Ids are references, not merely ordinals: taint entries cite
            // `caused_by_call`, flow entries cite `server:call_id`, and the
            // client-facing denial names "call N". Restarting the counter would
            // make every one of those ambiguous in a file spanning more than one
            // run — which is every real deployment, since the file is append-only
            // for the life of the operator. Highest id wins rather than last, so
            // a file that already contains repeats from earlier versions cannot
            // produce further collisions.
            next_id: text
                .lines()
                .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
                .filter_map(|v| v.get("id").and_then(serde_json::Value::as_u64))
                .max()
                .map_or(0, |highest| highest + 1),
            // A well-terminated file ends in a newline. Anything else means the
            // last write did not finish.
            needs_newline: !text.is_empty() && !text.ends_with('\n'),
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

    /// Append one entry, chaining it to the previous line.
    ///
    /// Chaining happens here rather than in each entry type, so a new kind of
    /// record cannot be added that forgets to participate in the chain.
    fn write(&self, entry: &impl Serialize) {
        // Phase 0 posture: a logging failure must NOT block the mediated call.
        // Here the ledger is an observability record, not the enforcement record.
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());

        let mut value = match serde_json::to_value(entry) {
            Ok(v) => v,
            Err(e) => {
                eprintln!("customhouse: ledger serialize failed (call still proceeds): {e}");
                return;
            }
        };
        if let serde_json::Value::Object(map) = &mut value {
            map.insert(
                "prev_hash".to_string(),
                serde_json::Value::String(state.prev_hash.clone()),
            );
        }
        let line = match serde_json::to_string(&value) {
            Ok(line) => line,
            Err(e) => {
                eprintln!("customhouse: ledger serialize failed (call still proceeds): {e}");
                return;
            }
        };

        let Some(file) = state.file.as_mut() else {
            return;
        };
        if let Err(e) = file.write_all(format!("{line}\n").as_bytes()) {
            eprintln!("customhouse: ledger write failed (call still proceeds): {e}");
            return;
        }
        // Advance the head only after the line is durably handed to the file, so
        // a failed write cannot leave the chain pointing at a line nobody has.
        state.prev_hash = hash_line(&line);
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

/// Why a ledger failed verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("cannot read ledger: {0}")]
    Read(#[source] std::io::Error),
    #[error("line {line}: not valid JSON: {source}")]
    Malformed {
        line: usize,
        #[source]
        source: serde_json::Error,
    },
    #[error("line {line}: no prev_hash field, so the chain cannot be followed")]
    MissingChain { line: usize },
    #[error(
        "line {line}: chain broken. Expected prev_hash {expected}, found {found}. \
         Everything before this line verifies; this line or the one before it was altered."
    )]
    Broken {
        line: usize,
        expected: String,
        found: String,
    },
}

/// Walk a ledger's hash chain.
///
/// Detects a point edit: altering any line changes its hash, so the following
/// line's `prev_hash` no longer matches and verification names that line.
///
/// This is **tamper-evident, not tamper-proof**. Nothing here is cryptographically
/// attributable to an author. An attacker who can write the file can recompute
/// every subsequent hash and produce a chain that verifies; what this closes is
/// the case of an entry being quietly edited or removed in place.
pub fn verify(path: &Path) -> Result<usize, VerifyError> {
    let text = std::fs::read_to_string(path).map_err(VerifyError::Read)?;
    let mut expected = GENESIS_HASH.to_string();
    let mut checked = 0usize;

    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let number = index + 1;
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|source| VerifyError::Malformed {
                line: number,
                source,
            })?;
        let found = value
            .get("prev_hash")
            .and_then(|v| v.as_str())
            .ok_or(VerifyError::MissingChain { line: number })?;
        if found != expected {
            return Err(VerifyError::Broken {
                line: number,
                expected,
                found: found.to_string(),
            });
        }
        expected = hash_line(line);
        checked += 1;
    }
    Ok(checked)
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
    fn every_entry_chains_to_the_one_before_it() {
        let home = tempfile::tempdir().unwrap();
        let ledger = Ledger::open_in(home.path());
        ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        ledger.record_metadata("web", "web__fetch", &PinOutcome::FirstSight);

        let entries = read_entries(ledger.path());
        assert_eq!(
            entries[0]["prev_hash"], GENESIS_HASH,
            "first entry anchors to genesis"
        );
        assert_eq!(verify(ledger.path()).unwrap(), 3);
    }

    #[test]
    fn a_point_edit_to_a_historical_entry_is_detected_and_named() {
        // The property the feature exists for: an entry quietly altered in place
        // breaks the chain at the *following* line, and verification says which.
        let home = tempfile::tempdir().unwrap();
        let ledger = Ledger::open_in(home.path());
        for _ in 0..4 {
            ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        }
        assert!(verify(ledger.path()).is_ok(), "clean ledger verifies");

        // Rewrite line 2's decision from deny-shaped to allow-shaped.
        let text = fs::read_to_string(ledger.path()).unwrap();
        let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
        lines[1] = lines[1].replace("\"tool\":\"web__fetch\"", "\"tool\":\"web__tampered\"");
        fs::write(ledger.path(), lines.join("\n") + "\n").unwrap();

        match verify(ledger.path()) {
            Err(VerifyError::Broken { line, .. }) => {
                assert_eq!(line, 3, "the break surfaces at the line after the edit");
            }
            other => panic!("expected a broken chain, got {other:?}"),
        }
    }

    #[test]
    fn appending_after_a_restart_keeps_the_chain_intact() {
        // A fresh process must resume the chain rather than restart it, or the
        // join would look like tampering forever.
        let home = tempfile::tempdir().unwrap();
        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        }
        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        }
        assert_eq!(
            verify(&home.path().join(LEDGER_FILE)).unwrap(),
            2,
            "both entries verify across the restart boundary"
        );
    }

    /// Cut the file mid-record, exactly as a crash between `write_all` and the
    /// next flush would leave it: no terminating newline.
    fn simulate_crash_mid_write(path: &Path, keep_bytes_from_end: usize) {
        let text = fs::read_to_string(path).unwrap();
        let cut = text.len() - keep_bytes_from_end;
        fs::write(path, &text[..cut]).unwrap();
        assert!(
            !fs::read_to_string(path).unwrap().ends_with('\n'),
            "the simulated crash must actually leave an unterminated line"
        );
    }

    #[test]
    fn a_record_truncated_by_a_crash_does_not_swallow_the_next_one() {
        // Appending onto an unterminated line concatenates two records into one
        // unparseable line: the crash costs its own partial record *and* the
        // first record of the next session, silently.
        let home = tempfile::tempdir().unwrap();
        let path = home.path().join(LEDGER_FILE);
        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
            ledger.record_call(&call("web__fetch", None), Some("web"), &allow());
        }
        simulate_crash_mid_write(&path, 25);
        let before = fs::read_to_string(&path).unwrap().lines().count();

        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("mail__send_email", None), Some("mail"), &allow());
        }

        let text = fs::read_to_string(&path).unwrap();
        assert_eq!(
            text.lines().count(),
            before + 1,
            "the new record must land on its own line, not inside the fragment"
        );
        let last = text.lines().next_back().unwrap();
        let parsed: Value =
            serde_json::from_str(last).expect("the record after a crash must be readable");
        assert_eq!(parsed["tool"], "mail__send_email");
    }

    #[test]
    fn ids_continue_across_a_restart_so_a_file_never_repeats_one() {
        // Ids are cited as references — `caused_by_call`, `server:call_id`, and
        // the denial text's "call N". A counter that restarts makes every one of
        // those ambiguous in a multi-session file.
        let home = tempfile::tempdir().unwrap();
        let mut assigned = Vec::new();
        for _ in 0..3 {
            let ledger = Ledger::open_in(home.path());
            assigned.push(ledger.record_call(&call("web__fetch", None), Some("web"), &allow()));
            assigned.push(ledger.record_call(&call("web__fetch", None), Some("web"), &allow()));
        }
        assert_eq!(assigned, vec![0, 1, 2, 3, 4, 5]);

        let ids: Vec<u64> = read_entries(&home.path().join(LEDGER_FILE))
            .iter()
            .map(|e| e["id"].as_u64().unwrap())
            .collect();
        let unique: std::collections::BTreeSet<u64> = ids.iter().copied().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "no id may repeat within one file: {ids:?}"
        );
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

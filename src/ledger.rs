//! The append-only ledger (DESIGN-v2.md §3-I5).
//!
//! Every mediated `tools/call` is recorded here — allowed and denied alike —
//! from the single chokepoint in `proxy::call_tool`. The ledger lives at
//! `<bulkhead-home>/ledger.jsonl`, inside the directory the §3 invariant gate
//! already protects, so a mediated call cannot be steered into reading or
//! truncating it (I-5 holds for free; the drift-catching test is below).
//!
//! Writer discipline: the file is opened in append mode and never rewritten.
//!
//! Phase 0 scope: entries carry only what a passthrough proxy actually knows —
//! id, timestamp, tool, resolved server, decision, and (on deny) the matched
//! path as operator detail. Session, taint labels, rule ids, arg shapes/digests,
//! and latency are Phase 1; they are left out, not stubbed.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use rmcp::model::CallToolRequestParams;
use serde::Serialize;

use crate::config::NAMESPACE_SEP;
use crate::invariant::{Assessment, Decision};
use crate::paths::bulkhead_home;

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
    /// Open the ledger at `<bulkhead-home>/ledger.jsonl` (production).
    pub fn open() -> Self {
        Self::open_in(&bulkhead_home())
    }

    /// Open the ledger under an explicit home directory (tests supply a tempdir).
    pub fn open_in(home: &Path) -> Self {
        let path = home.join(LEDGER_FILE);
        let sink = match Self::try_open(home, &path) {
            Ok(file) => Some(file),
            Err(e) => {
                eprintln!(
                    "bulkhead: ledger disabled — cannot open {}: {e}",
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

    /// Record one mediated call and its assessment. The deny detail is the
    /// matched protected path — operator-only, and safe here precisely because
    /// the ledger is unreadable through the mediated surface (I-5).
    pub fn record_call(&self, request: &CallToolRequestParams, assessment: &Assessment) {
        let (decision, detail) = match &assessment.decision {
            Decision::Allow => ("allow", None),
            Decision::Deny { .. } => (
                "deny",
                assessment
                    .matched_path
                    .as_ref()
                    .map(|p| p.display().to_string()),
            ),
        };
        let tool = request.name.to_string();
        let server = tool.split_once(NAMESPACE_SEP).map(|(s, _)| s.to_string());

        let entry = LedgerEntry {
            id: self.next_id.fetch_add(1, Ordering::Relaxed),
            ts_ms: now_ms(),
            tool,
            server,
            decision,
            detail,
        };
        self.write(&entry);
    }

    fn write(&self, entry: &LedgerEntry) {
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
                eprintln!("bulkhead: ledger serialize failed (call still proceeds): {e}");
                return;
            }
        };
        line.push('\n');
        if let Err(e) = file.write_all(line.as_bytes()) {
            eprintln!("bulkhead: ledger write failed (call still proceeds): {e}");
        }
    }
}

#[derive(Serialize)]
struct LedgerEntry {
    /// Monotonic within a single process run only; NOT stable across restarts.
    id: u64,
    ts_ms: u64,
    tool: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
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
            decision: Decision::Allow,
            matched_path: None,
        }
    }

    fn deny(path: &str) -> Assessment {
        Assessment {
            decision: Decision::Deny {
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
        ledger.record_call(&call("web__fetch", None), &allow());
        ledger.record_call(
            &call("fs__write", Some("/etc/x")),
            &deny("/home/u/.bulkhead/secret"),
        );

        let entries = read_entries(ledger.path());
        assert_eq!(entries.len(), 2);

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
        assert_eq!(entries[1]["detail"], "/home/u/.bulkhead/secret");
        assert_eq!(entries[1]["id"], 1);
    }

    #[test]
    fn reopening_appends_rather_than_truncating() {
        let home = tempfile::tempdir().unwrap();
        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("web__fetch", None), &allow());
        }
        {
            let ledger = Ledger::open_in(home.path());
            ledger.record_call(&call("web__fetch", None), &allow());
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
            matches!(invariants.evaluate(&read_the_ledger), Decision::Deny { .. }),
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
        ledger.record_call(&call("web__fetch", None), &allow()); // must not panic
    }
}

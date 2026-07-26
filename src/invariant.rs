//! Self-protection invariants (DESIGN-v2.md §3).
//!
//! These are compiled into the binary and evaluated *before* any policy rule.
//! They are derived from process facts (the Bulkhead home directory, the running
//! binary) and never from `bulkhead.toml` or any upstream input — an agent must
//! not be able to disarm Bulkhead through the very surface Bulkhead mediates.
//!
//! This module implements the mediated-`tools/call` half of I1/I2: a call is
//! denied if any of its path-like arguments resolves onto Bulkhead's own files.
//! The decision is a pure function of `(arguments, filesystem state)`: it reads
//! the local filesystem to canonicalize paths (as §3 requires — symlinks must be
//! resolved) but makes no network or model call and introduces no nondeterminism.
//!
//! ## Scope (v0.1)
//!
//! Path-like arguments are identified *heuristically* — a string that starts
//! with `~` or contains `/`. Per-server argument-schema understanding is Phase 1
//! (capability profiles), deliberately not attempted here.
//!
//! Catches: absolute paths, `~`-relative paths, relative paths with separators,
//! `..` traversal, symlinks anywhere on the path, and targets that do not exist
//! yet (e.g. a *write* into the home directory).
//!
//! Does NOT catch (documented, not hidden): bare filenames with no separator,
//! paths hidden inside encoded/base64 blobs (that is §7.4, Phase 1), exec/shell
//! string arguments (I3 → Escalate, Phase 1), and any argument whose path-ness
//! is only knowable from the server's schema. The shared [`crate::decision::Decision`]
//! is Allow/Deny only for now; `Escalate` arrives with the tiered policy engine
//! in Phase 1.

use std::path::{Path, PathBuf};

use rmcp::model::CallToolRequestParams;
use serde_json::Value;

use crate::decision::{Assessment, Decision};
use crate::paths::{bulkhead_home, resolve_path, resolve_target};

/// Client-facing denial reason. Deliberately generic: it names no path, so a
/// tainted argument is never echoed back into the model's context (§7.6).
/// Operator-facing detail (which path, which tool) belongs in the ledger.
const DENY_REASON: &str =
    "denied by Bulkhead self-protection: operation resolves onto Bulkhead's own files";

/// The resolved set of paths Bulkhead protects. Built once at startup; the
/// contents come only from process facts, never from configuration values.
#[derive(Debug, Clone)]
pub struct Invariants {
    /// Canonicalized protected roots. A resolved target is denied if it equals,
    /// or is a descendant of, any of these.
    protected_roots: Vec<PathBuf>,
}

impl Invariants {
    /// Resolve the protected set from the environment and the running binary.
    ///
    /// - the Bulkhead home directory (`BULKHEAD_HOME`, else `~/.bulkhead`), which
    ///   holds config, ledger, and pin store;
    /// - the running binary's containing directory (covers the binary itself);
    /// - the active config file, if one was loaded.
    pub fn resolve(config_path: Option<&Path>) -> Self {
        let mut roots = Vec::new();

        roots.push(resolve_path(&bulkhead_home()));

        if let Ok(exe) = std::env::current_exe() {
            let exe = resolve_path(&exe);
            // The containing directory covers the binary itself (I2).
            match exe.parent() {
                Some(dir) => roots.push(dir.to_path_buf()),
                None => roots.push(exe),
            }
        }

        if let Some(config_path) = config_path {
            roots.push(resolve_path(config_path));
        }

        Self::from_roots(roots)
    }

    /// Build directly from a set of roots, canonicalizing each so comparisons
    /// are against resolved paths. Primarily for tests, which supply temp dirs.
    pub fn from_roots(roots: Vec<PathBuf>) -> Self {
        Self {
            protected_roots: roots.iter().map(|r| resolve_path(r)).collect(),
        }
    }

    /// The gate. Deny the call if any path-like argument resolves onto a
    /// protected path; otherwise allow. Resolves each candidate once and returns
    /// the richer `Assessment` (operator detail included). Pure w.r.t. its inputs.
    pub fn assess(&self, request: &CallToolRequestParams) -> Assessment {
        let Some(arguments) = &request.arguments else {
            return Assessment::allow();
        };

        let mut candidates = Vec::new();
        for value in arguments.values() {
            collect_path_candidates(value, &mut candidates);
        }

        for raw in &candidates {
            let resolved = resolve_target(raw);
            if self.is_protected(&resolved) {
                return Assessment {
                    decision: Decision::Deny {
                        reason: DENY_REASON.to_string(),
                    },
                    matched_path: Some(resolved),
                };
            }
        }
        Assessment::allow()
    }

    /// Client-facing projection of `assess`: the `Decision` only, never the
    /// matched path. Callers on the client-error path use this.
    pub fn evaluate(&self, request: &CallToolRequestParams) -> Decision {
        self.assess(request).decision
    }

    /// True if `resolved` is one of, or lives inside, a protected root. Uses
    /// component-wise `starts_with`, so a sibling like `.bulkhead-evil` is *not*
    /// treated as being inside `.bulkhead`.
    fn is_protected(&self, resolved: &Path) -> bool {
        self.protected_roots
            .iter()
            .any(|root| resolved == root || resolved.starts_with(root))
    }
}

/// A string is a path candidate if it starts with `~` or contains a separator.
fn is_path_like(value: &str) -> bool {
    !value.is_empty() && (value.starts_with('~') || value.contains('/'))
}

/// Collect every path-like string in a JSON argument value, recursing into
/// arrays and nested objects.
fn collect_path_candidates(value: &Value, out: &mut Vec<String>) {
    match value {
        Value::String(s) => {
            if is_path_like(s) {
                out.push(s.clone());
            }
        }
        Value::Array(items) => {
            for item in items {
                collect_path_candidates(item, out);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                collect_path_candidates(item, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;

    fn call_with_path(path: &str) -> CallToolRequestParams {
        let mut arguments = serde_json::Map::new();
        arguments.insert("path".into(), Value::String(path.into()));
        CallToolRequestParams::new("fs__write").with_arguments(arguments)
    }

    fn is_deny(decision: Decision) -> bool {
        matches!(decision, Decision::Deny { .. })
    }

    fn path_str(path: PathBuf) -> String {
        path.to_str().expect("utf-8 path").to_string()
    }

    #[test]
    fn denies_path_resolving_inside_home() {
        let home = tempfile::tempdir().unwrap();
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);
        // Target need not exist: a write into the home dir must still be denied.
        let target = path_str(home.path().join("ledger.log"));
        assert!(is_deny(invariants.evaluate(&call_with_path(&target))));
    }

    #[test]
    fn denies_dotdot_traversal_into_home() {
        let home = tempfile::tempdir().unwrap();
        let sub = home.path().join("sub");
        fs::create_dir(&sub).unwrap();
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);
        // .../sub/../secret resolves back into home.
        let target = path_str(sub.join("..").join("secret"));
        assert!(is_deny(invariants.evaluate(&call_with_path(&target))));
    }

    #[test]
    fn denies_symlinked_directory_component_into_home() {
        let home = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        // The symlink is a *directory component*, not the leaf: outside/link -> home.
        let link = outside.path().join("link");
        symlink(home.path(), &link).unwrap();
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);
        let target = path_str(link.join("secret"));
        assert!(is_deny(invariants.evaluate(&call_with_path(&target))));
    }

    #[test]
    fn denies_path_targeting_the_binary() {
        let bin_dir = tempfile::tempdir().unwrap();
        let binary = bin_dir.path().join("bulkhead");
        fs::write(&binary, b"binary").unwrap();
        // Protect the binary's containing directory (I2).
        let invariants = Invariants::from_roots(vec![bin_dir.path().to_path_buf()]);
        assert!(is_deny(
            invariants.evaluate(&call_with_path(&path_str(binary)))
        ));
    }

    #[test]
    fn allows_unrelated_path() {
        let home = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);
        let target = path_str(elsewhere.path().join("data.txt"));
        assert_eq!(
            invariants.evaluate(&call_with_path(&target)),
            Decision::Allow
        );
    }

    #[test]
    fn allows_sibling_dir_sharing_a_name_prefix() {
        // The prefix-collision case: `.bulkhead-evil` must NOT be seen as being
        // inside `.bulkhead`. This is why the check is component-wise.
        let base = tempfile::tempdir().unwrap();
        let home = base.path().join("bulkhead");
        let sibling = base.path().join("bulkhead-evil");
        fs::create_dir(&home).unwrap();
        fs::create_dir(&sibling).unwrap();
        let invariants = Invariants::from_roots(vec![home]);
        let target = path_str(sibling.join("data.txt"));
        assert_eq!(
            invariants.evaluate(&call_with_path(&target)),
            Decision::Allow
        );
    }

    #[test]
    fn allows_non_path_tool_call() {
        let home = tempfile::tempdir().unwrap();
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);
        let mut arguments = serde_json::Map::new();
        arguments.insert(
            "text".into(),
            Value::String("hello through bulkhead".into()),
        );
        let request = CallToolRequestParams::new("mock__echo").with_arguments(arguments);
        assert_eq!(invariants.evaluate(&request), Decision::Allow);
    }

    #[test]
    fn allows_call_with_no_arguments() {
        let home = tempfile::tempdir().unwrap();
        let invariants = Invariants::from_roots(vec![home.path().to_path_buf()]);
        let request = CallToolRequestParams::new("mock__echo");
        assert_eq!(invariants.evaluate(&request), Decision::Allow);
    }
}

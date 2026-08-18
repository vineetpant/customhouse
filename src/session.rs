//! Session taint state (DESIGN-v2.md §6).
//!
//! A leaf module: pure state and pure queries, no I/O and no knowledge of the
//! proxy. The enforcement rule that consumes it lives in `flow`.
//!
//! ## Why session-scoped, and what that costs
//!
//! Customhouse sits at the tool boundary, so it can see *what entered the model's
//! context* and *what the model asked for next* — but nothing about how the
//! model mixed them. Per-variable information flow is therefore not available at
//! this vantage point, and claiming it would be a lie.
//!
//! v1 enforces the honest version: the session is tainted the moment a result
//! from an untrusted upstream is returned to the client, and stays tainted for
//! the rest of the session. Every subsequent sink call is evaluated against that
//! fact. The rule is coarse — it will block sink calls that were not actually
//! influenced — but it is *deterministic and unevadable by transformation*,
//! which is the property that matters. Coarseness is a false-positive cost,
//! measured and reported rather than hidden.

use std::collections::BTreeSet;

/// One reason a session became tainted: an untrusted upstream returned content
/// into the model's context.
///
/// Carries no content — only provenance. A denial explains *which* server and
/// *which* call tainted the session, never what the content said (§7.6), so a
/// tainted string can never be echoed back through the refusal itself.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct TaintSource {
    /// The upstream whose result tainted the session.
    pub server: String,
    /// The namespaced tool that returned it.
    pub tool: String,
    /// Ledger id of the call, so the full record can be looked up.
    pub call_id: u64,
    /// Who the source *asserted* authored this content, if the upstream declared
    /// an author field and the result carried a usable value (§17.3).
    ///
    /// This is the only value permitted to authorise a reply. It is read from a
    /// declared structured field, never found by searching the body — an
    /// attacker who writes the body must not be able to forge it.
    pub author: Option<String>,
}

/// Accumulated taint for one session.
///
/// Monotonic by design: taint is never cleared mid-session. The design's reset
/// paths (connection end, idle timeout, explicit consent-gated reset) are
/// session *lifecycle*, not policy — a session that could untaint itself on
/// request would provide no guarantee at all.
#[derive(Debug, Clone, Default)]
pub struct SessionTaint {
    sources: BTreeSet<TaintSource>,
}

impl SessionTaint {
    /// A fresh, untainted session.
    pub fn clean() -> Self {
        Self::default()
    }

    /// Whether any untrusted content has entered this session.
    pub fn is_tainted(&self) -> bool {
        !self.sources.is_empty()
    }

    /// Record that an untrusted upstream returned content into the session.
    /// Idempotent: the same server/tool/call is only recorded once.
    pub fn taint(&mut self, source: TaintSource) {
        self.sources.insert(source);
    }

    /// Every recorded cause, in stable order — the provenance chain a denial
    /// cites and the ledger records.
    pub fn sources(&self) -> impl Iterator<Item = &TaintSource> {
        self.sources.iter()
    }

    /// The distinct upstreams that have tainted this session.
    pub fn tainting_servers(&self) -> BTreeSet<&str> {
        self.sources.iter().map(|s| s.server.as_str()).collect()
    }

    /// The asserted authors of every taint source that carried one.
    ///
    /// A source with no author contributes nothing, which makes the set
    /// *smaller* rather than more permissive — but see `all_sources_have_authors`:
    /// an exemption also requires that no source is missing one.
    pub fn authors(&self) -> Vec<String> {
        self.sources
            .iter()
            .filter_map(|s| s.author.clone())
            .collect()
    }

    /// Whether every taint source asserted an author.
    ///
    /// If even one source is anonymous, its content could reach a recipient who
    /// did not write it, so the exemption must not fire (§17.4).
    pub fn all_sources_have_authors(&self) -> bool {
        !self.sources.is_empty() && self.sources.iter().all(|s| s.author.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(server: &str, tool: &str, call_id: u64) -> TaintSource {
        TaintSource {
            server: server.to_string(),
            tool: tool.to_string(),
            call_id,
            author: None,
        }
    }

    #[test]
    fn a_fresh_session_is_clean() {
        assert!(!SessionTaint::clean().is_tainted());
    }

    #[test]
    fn one_untrusted_result_taints_the_session() {
        let mut taint = SessionTaint::clean();
        taint.taint(source("fs", "fs__read_text_file", 7));
        assert!(taint.is_tainted());
        assert_eq!(taint.tainting_servers(), ["fs"].into_iter().collect());
    }

    #[test]
    fn taint_is_monotonic_and_accumulates_distinct_sources() {
        let mut taint = SessionTaint::clean();
        taint.taint(source("fs", "fs__read_text_file", 1));
        taint.taint(source("fs", "fs__read_text_file", 1)); // duplicate
        taint.taint(source("web", "web__fetch", 2));

        assert_eq!(taint.sources().count(), 2, "duplicates collapse");
        assert_eq!(
            taint.tainting_servers(),
            ["fs", "web"].into_iter().collect(),
            "both upstreams are named in the provenance chain"
        );
    }

    #[test]
    fn sources_carry_provenance_but_never_content() {
        // The struct has no content field by construction — a denial can cite
        // where taint came from without ever quoting what it said (§7.6).
        let mut taint = SessionTaint::clean();
        taint.taint(source("fs", "fs__read_text_file", 42));
        let first = taint.sources().next().unwrap();
        assert_eq!((first.server.as_str(), first.call_id), ("fs", 42));
    }
}

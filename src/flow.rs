//! The R3 flow rule: untrusted-derived sessions may not reach sinks (§7–§8).
//!
//! This is the rule the whole architecture exists for. It is a pure function of
//! `(tool name, session taint, config)` — no I/O, no model, no clock — so it is
//! exhaustively testable and produces the same verdict every time.
//!
//! ## The rule
//!
//! 1. A tool that is not a sink is always allowed. Reading is never blocked.
//! 2. A sink in a clean session is allowed. Sinks are not forbidden; sinks
//!    *after untrusted input* are.
//! 3. A sink in a tainted session is denied — or escalated, if the operator has
//!    set that class to `require_approval`.
//!
//! ## What makes it the moat
//!
//! Taint is session-scoped and *cross-server*: content read through one upstream
//! blocks a sink on a different upstream. A proxy that wraps a single server
//! cannot express this rule at all, because it never sees both halves of the
//! flow. That is the demo no per-server gateway can reproduce.
//!
//! ## What it deliberately does not claim
//!
//! It does not know whether the untrusted content actually influenced the sink
//! call — only that it *could* have, because it entered the same session. That
//! over-blocks, and the false-positive rate is measured and published rather
//! than hidden. The trade is deliberate: the rule cannot be evaded by
//! transforming, summarising or re-encoding the tainted content, because it
//! never inspects content at all.

use crate::config::{FlowConfig, SinkMode};
use crate::decision::Decision;
use crate::session::{SessionTaint, TaintSource};
use crate::sink::{SinkClass, SinkMap};

/// The operator-side result of the flow rule: the client-facing decision plus
/// the provenance that justified it, for the ledger.
#[derive(Debug, Clone)]
pub struct FlowAssessment {
    pub decision: Decision,
    /// The sink class this call belongs to, if it is a sink at all.
    pub sink_class: Option<SinkClass>,
    /// The taint sources cited, empty when the call was allowed.
    pub taint_sources: Vec<TaintSource>,
}

impl FlowAssessment {
    fn allow(sink_class: Option<SinkClass>) -> Self {
        Self {
            decision: Decision::Allow,
            sink_class,
            taint_sources: Vec::new(),
        }
    }
}

/// The configured flow policy: what counts as a sink, and what to do about it.
#[derive(Debug, Clone)]
pub struct FlowPolicy {
    sinks: SinkMap,
    modes: FlowConfig,
}

impl FlowPolicy {
    pub fn new(sinks: SinkMap, modes: FlowConfig) -> Self {
        Self { sinks, modes }
    }

    /// Evaluate one call against the session's accumulated taint.
    pub fn assess(&self, namespaced_tool: &str, taint: &SessionTaint) -> FlowAssessment {
        let Some(class) = self.sinks.classify(namespaced_tool) else {
            // Not a sink: nothing to enforce. Reads stay unblocked so a tainted
            // session can still do useful work.
            return FlowAssessment::allow(None);
        };

        if !taint.is_tainted() {
            return FlowAssessment::allow(Some(class));
        }

        let sources: Vec<TaintSource> = taint.sources().cloned().collect();
        let reason = explain(class, &sources);
        let decision = match self.modes.mode_for(class) {
            SinkMode::Deny => Decision::Deny { reason },
            SinkMode::RequireApproval => Decision::Escalate {
                reason: format!(
                    "{reason}. An operator can approve this class for one retry \
                     with `penstock approve {}`",
                    class.as_str()
                ),
            },
        };

        FlowAssessment {
            decision,
            sink_class: Some(class),
            taint_sources: sources,
        }
    }
}

/// Build the client-facing explanation.
///
/// Names the upstreams and call ids that tainted the session, and the sink class
/// being blocked — never a byte of the content itself (§7.6). The model reads
/// this error, so quoting the untrusted text here would re-inject the payload
/// through Penstock's own mouth.
fn explain(class: SinkClass, sources: &[TaintSource]) -> String {
    let origins: Vec<String> = sources
        .iter()
        .map(|s| format!("{} (call {})", s.server, s.call_id))
        .collect();
    format!(
        "denied by Penstock flow policy: this session received untrusted content from {}, \
         so calls in the {} class are blocked for the rest of the session",
        origins.join(", "),
        class.as_str()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tainted_by(server: &str, tool: &str, call_id: u64) -> SessionTaint {
        let mut taint = SessionTaint::clean();
        taint.taint(TaintSource {
            server: server.to_string(),
            tool: tool.to_string(),
            call_id,
        });
        taint
    }

    fn policy() -> FlowPolicy {
        FlowPolicy::new(SinkMap::default(), FlowConfig::default())
    }

    #[test]
    fn non_sink_calls_are_allowed_even_when_tainted() {
        let taint = tainted_by("fs", "fs__read_text_file", 1);
        let assessment = policy().assess("fs__read_text_file", &taint);
        assert_eq!(assessment.decision, Decision::Allow);
        assert_eq!(assessment.sink_class, None);
    }

    #[test]
    fn sinks_are_allowed_in_a_clean_session() {
        let assessment = policy().assess("mail__send_email", &SessionTaint::clean());
        assert_eq!(assessment.decision, Decision::Allow);
        assert_eq!(
            assessment.sink_class,
            Some(SinkClass::ExternalSend),
            "still recognised as a sink, just not blocked"
        );
    }

    #[test]
    fn a_sink_in_a_tainted_session_is_denied() {
        let taint = tainted_by("fs", "fs__read_text_file", 3);
        let assessment = policy().assess("mail__send_email", &taint);
        assert!(matches!(assessment.decision, Decision::Deny { .. }));
        assert_eq!(assessment.sink_class, Some(SinkClass::ExternalSend));
        assert_eq!(assessment.taint_sources.len(), 1);
    }

    #[test]
    fn taint_from_one_server_blocks_a_sink_on_another() {
        // The cross-server property: this is the rule a per-server proxy cannot
        // express, because it never observes both halves of the flow.
        let taint = tainted_by("fs", "fs__read_text_file", 1);
        let assessment = policy().assess("mail__send_email", &taint);

        assert!(matches!(assessment.decision, Decision::Deny { .. }));
        let Decision::Deny { reason } = &assessment.decision else {
            unreachable!()
        };
        assert!(reason.contains("fs"), "must name the tainting server");
        assert!(reason.contains("call 1"), "must name the tainting call");
        assert!(
            reason.contains("external_send"),
            "must name the blocked sink class"
        );
    }

    #[test]
    fn require_approval_escalates_instead_of_denying() {
        let modes = FlowConfig {
            external_send: SinkMode::RequireApproval,
            ..FlowConfig::default()
        };
        let policy = FlowPolicy::new(SinkMap::default(), modes);
        let taint = tainted_by("fs", "fs__read_text_file", 1);

        let assessment = policy.assess("mail__send_email", &taint);
        let Decision::Escalate { reason } = &assessment.decision else {
            panic!("expected escalation, got {:?}", assessment.decision)
        };
        assert!(reason.contains("penstock approve external_send"));

        // Other classes keep the hard default.
        let payment = policy.assess("bank__transfer_funds", &taint);
        assert!(matches!(payment.decision, Decision::Deny { .. }));
    }

    #[test]
    fn multiple_taint_sources_are_all_cited() {
        let mut taint = tainted_by("fs", "fs__read_text_file", 1);
        taint.taint(TaintSource {
            server: "web".into(),
            tool: "web__fetch".into(),
            call_id: 2,
        });
        let assessment = policy().assess("mail__send_email", &taint);
        let Decision::Deny { reason } = &assessment.decision else {
            unreachable!()
        };
        assert!(reason.contains("fs") && reason.contains("web"));
        assert_eq!(assessment.taint_sources.len(), 2);
    }

    #[test]
    fn the_explanation_carries_provenance_but_never_content() {
        // TaintSource has no content field, so the explanation physically cannot
        // quote the untrusted text — the model reading this error cannot be
        // re-injected by it.
        let taint = tainted_by("fs", "fs__read_text_file", 9);
        let assessment = policy().assess("mail__send_email", &taint);
        let Decision::Deny { reason } = &assessment.decision else {
            unreachable!()
        };
        assert!(reason.contains("fs (call 9)"));
        assert!(
            !reason.contains("IGNORE"),
            "no payload text can appear here"
        );
    }
}

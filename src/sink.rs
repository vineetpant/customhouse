//! Sink taxonomy: which tools can move money or move data out (DESIGN-v2.md §8).
//!
//! A leaf module — pure classification, no I/O and no policy. `flow` decides
//! what to do about a sink; this only says whether a tool *is* one.
//!
//! ## Matching is on the bare tool name
//!
//! Patterns are matched against the tool's own name with the server namespace
//! stripped (`mail__send_email` → `send_email`), because what makes a tool a
//! sink is its *effect*, not which server happens to host it. An explicit
//! namespaced pattern still works for operators who want to pin one server's
//! tool specifically.
//!
//! ## Why the built-in map is deliberately narrow
//!
//! False positives are a headline metric for this release, and every default
//! pattern is a chance to block a benign call. So the built-in map covers only
//! names that are unambiguous about leaving the machine — no generic `write*`,
//! because writing a local file is not egress and classifying it as one would
//! block ordinary work and inflate the false-positive rate for nothing.
//! Operators extend the map for their own tools; that is expected, not a gap.

use serde::Deserialize;

/// What kind of damage a sink can do. Ordered most-severe first, which is also
/// the order rules are evaluated, so `send_money` classifies as a payment
/// transfer rather than merely an external send.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkClass {
    /// Moves money.
    PaymentTransfer,
    /// Sends to a recipient: email, chat, webhook, notification.
    ExternalSend,
    /// Pushes data off the machine: uploads, object stores, publishing.
    DataEgress,
}

impl SinkClass {
    /// Parse the stable identifier, for CLI arguments.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "payment_transfer" => Some(SinkClass::PaymentTransfer),
            "external_send" => Some(SinkClass::ExternalSend),
            "data_egress" => Some(SinkClass::DataEgress),
            _ => None,
        }
    }

    /// Every class, for CLI help and reports.
    pub fn all() -> [SinkClass; 3] {
        [
            SinkClass::PaymentTransfer,
            SinkClass::ExternalSend,
            SinkClass::DataEgress,
        ]
    }

    /// Stable identifier used in config, ledger records and denial messages.
    pub fn as_str(&self) -> &'static str {
        match self {
            SinkClass::PaymentTransfer => "payment_transfer",
            SinkClass::ExternalSend => "external_send",
            SinkClass::DataEgress => "data_egress",
        }
    }
}

/// One operator-supplied classification rule.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkRule {
    /// Glob-ish pattern: exact, `prefix*`, `*suffix`, or `*contains*`.
    pub pattern: String,
    pub class: SinkClass,
}

impl SinkRule {
    pub fn new(pattern: impl Into<String>, class: SinkClass) -> Self {
        Self {
            pattern: pattern.into(),
            class,
        }
    }
}

/// The active classification map: operator rules first, then the built-ins.
#[derive(Debug, Clone)]
pub struct SinkMap {
    rules: Vec<SinkRule>,
}

impl Default for SinkMap {
    fn default() -> Self {
        Self::with_overrides(Vec::new())
    }
}

impl SinkMap {
    /// Built-in rules, with operator rules taking precedence over them.
    pub fn with_overrides(mut overrides: Vec<SinkRule>) -> Self {
        overrides.extend(builtin_rules());
        Self { rules: overrides }
    }

    /// Classify a namespaced tool name, or `None` if it is not a sink.
    /// First matching rule wins, so operator overrides and the severity
    /// ordering of the built-ins both hold.
    pub fn classify(&self, namespaced_tool: &str) -> Option<SinkClass> {
        let bare = bare_name(namespaced_tool);
        self.rules
            .iter()
            .find(|rule| {
                matches_pattern(&rule.pattern, bare)
                    || matches_pattern(&rule.pattern, namespaced_tool)
            })
            .map(|rule| rule.class)
    }
}

/// Strip the `server__` namespace Customhouse adds, leaving the tool's own name.
fn bare_name(namespaced: &str) -> &str {
    match namespaced.split_once(crate::config::NAMESPACE_SEP) {
        Some((_, bare)) => bare,
        None => namespaced,
    }
}

/// Hand-rolled glob: exact, `prefix*`, `*suffix`, `*contains*`. Deliberately not
/// a regex or glob crate — the dependency surface of the enforcement path is
/// itself a security property, and this is the whole feature.
fn matches_pattern(pattern: &str, name: &str) -> bool {
    match (pattern.strip_prefix('*'), pattern.strip_suffix('*')) {
        // *contains*
        (Some(rest), Some(_)) => {
            let inner = &rest[..rest.len().saturating_sub(1)];
            !inner.is_empty() && name.contains(inner)
        }
        // *suffix
        (Some(suffix), None) => name.ends_with(suffix),
        // prefix*
        (None, Some(prefix)) => name.starts_with(prefix),
        // exact
        (None, None) => pattern == name,
    }
}

/// The built-in map. Severity order matters: payment rules are checked before
/// send rules so `send_money` is treated as moving money, not merely sending.
fn builtin_rules() -> Vec<SinkRule> {
    use SinkClass::*;
    vec![
        // Money.
        SinkRule::new("*transfer*", PaymentTransfer),
        SinkRule::new("*payment*", PaymentTransfer),
        SinkRule::new("send_money*", PaymentTransfer),
        SinkRule::new("pay*", PaymentTransfer),
        SinkRule::new("charge*", PaymentTransfer),
        // Sending to a recipient.
        SinkRule::new("send*", ExternalSend),
        SinkRule::new("*email*", ExternalSend),
        SinkRule::new("*webhook*", ExternalSend),
        SinkRule::new("post*", ExternalSend),
        SinkRule::new("notify*", ExternalSend),
        // Pushing data off the machine.
        SinkRule::new("*upload*", DataEgress),
        SinkRule::new("publish*", DataEgress),
        SinkRule::new("put_object*", DataEgress),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_forms_all_work() {
        assert!(matches_pattern("send_email", "send_email"), "exact");
        assert!(matches_pattern("send*", "send_email"), "prefix");
        assert!(matches_pattern("*_email", "send_email"), "suffix");
        assert!(matches_pattern("*transfer*", "do_transfer_now"), "contains");
        assert!(!matches_pattern("send*", "resend"), "prefix is anchored");
        assert!(
            !matches_pattern("send_email", "send_email_2"),
            "exact is exact"
        );
    }

    #[test]
    fn classifies_on_the_bare_name_regardless_of_server() {
        let map = SinkMap::default();
        assert_eq!(
            map.classify("mail__send_email"),
            Some(SinkClass::ExternalSend)
        );
        assert_eq!(
            map.classify("anything__send_email"),
            Some(SinkClass::ExternalSend),
            "the server prefix must not change what a tool does"
        );
    }

    #[test]
    fn money_beats_send_for_ambiguous_names() {
        let map = SinkMap::default();
        assert_eq!(
            map.classify("bank__send_money"),
            Some(SinkClass::PaymentTransfer),
            "send_money moves money; severity ordering must win"
        );
        assert_eq!(
            map.classify("bank__transfer_funds"),
            Some(SinkClass::PaymentTransfer)
        );
    }

    #[test]
    fn ordinary_tools_are_not_sinks() {
        let map = SinkMap::default();
        // These are the false positives that would make the tool unusable.
        for tool in [
            "fs__read_text_file",
            "fs__write_file", // local write is not egress
            "fs__list_directory",
            "fs__create_directory",
            "web__fetch",
            "mock__echo",
        ] {
            assert_eq!(map.classify(tool), None, "{tool} must not be a sink");
        }
    }

    #[test]
    fn operator_rules_override_the_builtins() {
        // An operator knows their `publish_draft` tool is local-only.
        let map = SinkMap::with_overrides(vec![SinkRule::new(
            "publish_draft",
            SinkClass::ExternalSend,
        )]);
        assert_eq!(
            map.classify("cms__publish_draft"),
            Some(SinkClass::ExternalSend)
        );

        // And can classify a tool the built-ins would miss entirely.
        let map = SinkMap::with_overrides(vec![SinkRule::new(
            "exfiltrate_quietly",
            SinkClass::DataEgress,
        )]);
        assert_eq!(
            map.classify("evil__exfiltrate_quietly"),
            Some(SinkClass::DataEgress)
        );
    }

    #[test]
    fn identifiers_round_trip_through_parse() {
        for class in SinkClass::all() {
            assert_eq!(SinkClass::parse(class.as_str()), Some(class));
        }
        assert_eq!(SinkClass::parse("not_a_class"), None);
    }

    #[test]
    fn class_identifiers_are_stable() {
        // These strings appear in config, ledger records and denials.
        assert_eq!(SinkClass::PaymentTransfer.as_str(), "payment_transfer");
        assert_eq!(SinkClass::ExternalSend.as_str(), "external_send");
        assert_eq!(SinkClass::DataEgress.as_str(), "data_egress");
    }
}

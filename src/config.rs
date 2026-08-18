//! Customhouse configuration: the set of upstream MCP servers to aggregate.
//!
//! Configuration is loaded once at startup and never re-read mid-flight, so a
//! change to the running policy always requires an action outside the mediated
//! surface (see the self-protection invariants in DESIGN-v2.md §3).

use serde::Deserialize;
use std::path::Path;

use crate::sink::{SinkClass, SinkRule};

/// The separator between an upstream's name and a tool's own name in the
/// namespaced identifier Customhouse exposes to the client (`web__fetch`). Upstream
/// names may not contain it, so routing can split on the first occurrence.
pub const NAMESPACE_SEP: &str = "__";

/// Top-level configuration, deserialized from `customhouse.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// One entry per upstream MCP server, written as `[[upstream]]` tables.
    #[serde(default, rename = "upstream")]
    pub upstreams: Vec<UpstreamConfig>,
    /// Operator sink classifications, written as `[[sink]]` tables. These take
    /// precedence over the built-in map in [`crate::sink`].
    #[serde(default, rename = "sink")]
    pub sinks: Vec<SinkRule>,
    /// Per-sink-class enforcement modes, written as a `[flow]` table.
    #[serde(default)]
    pub flow: FlowConfig,
}

/// How to launch and identify a single upstream MCP server.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpstreamConfig {
    /// Stable, unique name used to namespace this server's tools.
    pub name: String,
    /// Executable to spawn; the server speaks MCP over its stdio.
    pub command: String,
    /// Arguments passed to `command`.
    #[serde(default)]
    pub args: Vec<String>,
    /// Whether results from this server may be treated as trusted input.
    /// Defaults to untrusted: an operator must positively assert trust, so
    /// forgetting to classify a server fails safe rather than silently
    /// admitting its content as clean.
    #[serde(default)]
    pub trust: TrustClass,
    /// Which field of this server's *results* asserts who authored the content
    /// (e.g. `"from"` on a ticket or mail server).
    ///
    /// Read structurally from the result, never by searching content: an
    /// attacker who can write a message body must not be able to forge the
    /// value that authorises a reply (§17.2). Absent means no author is ever
    /// known for this upstream, so destination classification never fires and
    /// the stricter session rule stands.
    #[serde(default)]
    pub author_field: Option<String>,
    /// Which argument names of this server's *sink tools* carry recipients
    /// (e.g. `["to", "cc", "bcc"]`).
    ///
    /// Declared rather than guessed: inferring which argument is the recipient
    /// risks authorising on a field the attacker chose. Absent means recipients
    /// cannot be identified, so the exemption never fires (§17.4).
    #[serde(default)]
    pub recipient_fields: Vec<String>,
}

/// Whether content returned by an upstream is trusted input.
///
/// Default-deny attribution (§7.1): content is untrusted unless positively
/// attributed to a trusted origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// Results may enter the session without tainting it.
    Trusted,
    /// Results taint the session when returned to the client.
    #[default]
    Untrusted,
}

impl TrustClass {
    pub fn is_untrusted(&self) -> bool {
        matches!(self, TrustClass::Untrusted)
    }
}

/// What Customhouse does when a tainted session reaches a sink, per sink class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkMode {
    /// Refuse outright. The default: a deterministic block is the guarantee
    /// this design is built to make.
    #[default]
    Deny,
    /// Refuse, but tell the operator how to approve a retry. Intended for sink
    /// classes where measured false positives make a hard block impractical.
    RequireApproval,
}

/// Enforcement mode per sink class. Every class defaults to `deny`.
#[derive(Debug, Clone, Copy, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FlowConfig {
    #[serde(default)]
    pub payment_transfer: SinkMode,
    #[serde(default)]
    pub external_send: SinkMode,
    #[serde(default)]
    pub data_egress: SinkMode,
}

impl FlowConfig {
    /// The configured mode for a sink class.
    pub fn mode_for(&self, class: SinkClass) -> SinkMode {
        match class {
            SinkClass::PaymentTransfer => self.payment_transfer,
            SinkClass::ExternalSend => self.external_send,
            SinkClass::DataEgress => self.data_egress,
        }
    }
}

/// Reasons a configuration is rejected. Customhouse fails closed on any of them.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("failed to read config file: {0}")]
    Read(#[source] std::io::Error),
    #[error("failed to parse config: {0}")]
    Parse(#[source] toml::de::Error),
    #[error("an upstream has an empty name")]
    EmptyName,
    #[error("upstream name `{0}` is used more than once")]
    DuplicateName(String),
    #[error("upstream name `{0}` must not contain the namespace separator `{NAMESPACE_SEP}`")]
    NameContainsSeparator(String),
}

impl Config {
    /// Parse configuration from a TOML string and validate it.
    pub fn from_toml_str(s: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(s).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration from `path`, or return an empty configuration if
    /// `path` is `None`. An empty configuration aggregates no upstreams.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        match path {
            None => Ok(Config::default()),
            Some(path) => {
                let text = std::fs::read_to_string(path).map_err(ConfigError::Read)?;
                Config::from_toml_str(&text)
            }
        }
    }

    /// Reject names that would break namespacing or routing, naming the exact
    /// cause so a misconfiguration is easy to fix.
    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            let name = upstream.name.as_str();
            if name.is_empty() {
                return Err(ConfigError::EmptyName);
            }
            if name.contains(NAMESPACE_SEP) {
                return Err(ConfigError::NameContainsSeparator(upstream.name.clone()));
            }
            if !seen.insert(name) {
                return Err(ConfigError::DuplicateName(upstream.name.clone()));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_config_has_no_upstreams() {
        let config = Config::from_toml_str("").unwrap();
        assert!(config.upstreams.is_empty());
    }

    #[test]
    fn parses_upstream_tables() {
        let config = Config::from_toml_str(
            r#"
            [[upstream]]
            name = "web"
            command = "web-fetch"
            args = ["--stdio"]

            [[upstream]]
            name = "mail"
            command = "mail-server"
            "#,
        )
        .unwrap();

        assert_eq!(config.upstreams.len(), 2);
        assert_eq!(config.upstreams[0].name, "web");
        assert_eq!(config.upstreams[0].command, "web-fetch");
        assert_eq!(config.upstreams[0].args, ["--stdio"]);
        assert!(config.upstreams[1].args.is_empty());
    }

    #[test]
    fn rejects_duplicate_names() {
        let result = Config::from_toml_str(
            r#"
            [[upstream]]
            name = "web"
            command = "a"
            [[upstream]]
            name = "web"
            command = "b"
            "#,
        );
        assert!(matches!(result, Err(ConfigError::DuplicateName(name)) if name == "web"));
    }

    #[test]
    fn rejects_names_containing_separator() {
        let result = Config::from_toml_str(
            r#"
            [[upstream]]
            name = "we__b"
            command = "a"
            "#,
        );
        assert!(matches!(result, Err(ConfigError::NameContainsSeparator(_))));
    }

    #[test]
    fn rejects_empty_name() {
        let result = Config::from_toml_str(
            r#"
            [[upstream]]
            name = ""
            command = "a"
            "#,
        );
        assert!(matches!(result, Err(ConfigError::EmptyName)));
    }

    #[test]
    fn an_unclassified_upstream_defaults_to_untrusted() {
        // Forgetting to classify a server must fail safe. If this ever flips,
        // an operator who adds a server and forgets `trust` silently admits its
        // content as clean, and the whole flow rule stops meaning anything.
        let config = Config::from_toml_str(
            r#"
            [[upstream]]
            name = "web"
            command = "web-server"
            "#,
        )
        .unwrap();
        assert_eq!(config.upstreams[0].trust, TrustClass::Untrusted);
        assert!(config.upstreams[0].trust.is_untrusted());
    }

    #[test]
    fn trust_can_be_asserted_explicitly() {
        let config = Config::from_toml_str(
            r#"
            [[upstream]]
            name = "internal"
            command = "internal-server"
            trust = "trusted"
            "#,
        )
        .unwrap();
        assert_eq!(config.upstreams[0].trust, TrustClass::Trusted);
        assert!(!config.upstreams[0].trust.is_untrusted());
    }

    #[test]
    fn sink_modes_default_to_deny_for_every_class() {
        let config = Config::from_toml_str("").unwrap();
        for class in [
            SinkClass::PaymentTransfer,
            SinkClass::ExternalSend,
            SinkClass::DataEgress,
        ] {
            assert_eq!(
                config.flow.mode_for(class),
                SinkMode::Deny,
                "{} must default to deny",
                class.as_str()
            );
        }
    }

    #[test]
    fn sink_rules_and_modes_parse() {
        let config = Config::from_toml_str(
            r#"
            [[sink]]
            pattern = "dispatch_*"
            class = "external_send"

            [flow]
            external_send = "require_approval"
            "#,
        )
        .unwrap();

        assert_eq!(config.sinks.len(), 1);
        assert_eq!(config.sinks[0].pattern, "dispatch_*");
        assert_eq!(config.sinks[0].class, SinkClass::ExternalSend);
        assert_eq!(
            config.flow.mode_for(SinkClass::ExternalSend),
            SinkMode::RequireApproval
        );
        assert_eq!(
            config.flow.mode_for(SinkClass::PaymentTransfer),
            SinkMode::Deny,
            "unset classes keep the safe default"
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        assert!(Config::from_toml_str("bogus = true").is_err());
    }
}

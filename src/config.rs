//! Penstock configuration: the set of upstream MCP servers to aggregate.
//!
//! Configuration is loaded once at startup and never re-read mid-flight, so a
//! change to the running policy always requires an action outside the mediated
//! surface (see the self-protection invariants in DESIGN-v2.md §3).

use serde::Deserialize;
use std::path::Path;

/// The separator between an upstream's name and a tool's own name in the
/// namespaced identifier Penstock exposes to the client (`web__fetch`). Upstream
/// names may not contain it, so routing can split on the first occurrence.
pub const NAMESPACE_SEP: &str = "__";

/// Top-level configuration, deserialized from `penstock.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// One entry per upstream MCP server, written as `[[upstream]]` tables.
    #[serde(default, rename = "upstream")]
    pub upstreams: Vec<UpstreamConfig>,
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
}

/// Reasons a configuration is rejected. Penstock fails closed on any of them.
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
    fn rejects_unknown_fields() {
        assert!(Config::from_toml_str("bogus = true").is_err());
    }
}

//! `customhouse init` — read the MCP servers an agent client already launches and
//! write a starting `customhouse.toml`.
//!
//! Depends on `config` and `sink` (both at or below it in the dependency order)
//! and imports no policy module. The parsing and rendering here are pure: file
//! discovery returns candidate paths, the caller reads them, and everything that
//! decides what the config *says* is a function of the bytes it was given. That
//! keeps the interesting part testable without touching a real home directory.
//!
//! ## What this deliberately does not do
//!
//! It never writes `trust = "trusted"`, for any server, under any heuristic.
//! There is no allowlist of "obviously safe" vendors here and no inference from
//! a command name. Trust is the single assertion that decides whether content
//! taints a session, so it has to be made by a person who knows what the server
//! actually reaches. A generated file that guessed trust would hand a user a
//! policy they never agreed to, and the failure would be silent.
//!
//! The consequence is a strict first run: with every upstream untrusted, any
//! session that reads anything is tainted, and sinks are refused or escalated
//! from then on. That is the correct first impression. The tool's whole claim is
//! that flows are refused by default; a generated config that felt permissive
//! would be advertising the opposite of what it does.

use std::path::PathBuf;

use crate::config::NAMESPACE_SEP;

/// An upstream recovered from a client's config, ready to be written out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredServer {
    pub name: String,
    pub command: String,
    pub args: Vec<String>,
    /// Which client config it came from, so the emitted file can say.
    pub source: String,
}

/// A server that was found but not written, and why.
///
/// Skipped entries are carried rather than dropped: a server silently missing
/// from the generated config would look like Customhouse is mediating it when it
/// is not, which is the worst failure this command could have.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedServer {
    pub name: String,
    pub reason: SkipReason,
    pub source: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SkipReason {
    /// Declared a `url`/`type` rather than a command. Customhouse launches stdio
    /// child processes; it cannot front a server it does not spawn.
    NotStdio,
    /// No `command` field, so there is nothing to launch.
    NoCommand,
    /// A server of this name was already taken from an earlier config.
    DuplicateName,
    /// The name would break tool namespacing (`web__fetch` splits on the first
    /// `__`), so routing could not recover the server.
    UnusableName,
}

impl SkipReason {
    pub fn explain(&self) -> &'static str {
        match self {
            SkipReason::NotStdio => {
                "not a stdio server — Customhouse mediates servers it launches itself"
            }
            SkipReason::NoCommand => "no `command` field, so there is nothing to launch",
            SkipReason::DuplicateName => {
                "a server with this name was already taken from an earlier config"
            }
            SkipReason::UnusableName => {
                "name is empty or contains `__`, which tool namespacing reserves"
            }
        }
    }
}

/// Everything one or more client configs yielded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovery {
    pub servers: Vec<DiscoveredServer>,
    pub skipped: Vec<SkippedServer>,
}

impl Discovery {
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty() && self.skipped.is_empty()
    }

    /// Read one client config's `mcpServers` map.
    ///
    /// Accumulates, so several client configs can be absorbed into one
    /// `Discovery`. A server already claimed by an earlier config is recorded as
    /// a duplicate rather than replacing it: first read wins, and discovery
    /// order is fixed, so the result does not depend on what the filesystem
    /// happened to return first.
    pub fn absorb(&mut self, source: &str, json: &str) -> Result<(), InitError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| InitError::Parse {
                path: source.to_string(),
                source: e,
            })?;

        // Absent or empty `mcpServers` is not an error: a client can legitimately
        // have a config with no MCP servers in it.
        let Some(servers) = value.get("mcpServers").and_then(|v| v.as_object()) else {
            return Ok(());
        };

        for (name, entry) in servers {
            let skip = |reason| SkippedServer {
                name: name.clone(),
                reason,
                source: source.to_string(),
            };

            if name.is_empty() || name.contains(NAMESPACE_SEP) {
                self.skipped.push(skip(SkipReason::UnusableName));
                continue;
            }
            if self.servers.iter().any(|s| &s.name == name) {
                self.skipped.push(skip(SkipReason::DuplicateName));
                continue;
            }
            // A remote server is identified by what it *has* (a url), not by the
            // absence of a command, so the two cases stay distinguishable in the
            // report the user reads.
            if entry.get("url").is_some() || entry.get("type").is_some() {
                self.skipped.push(skip(SkipReason::NotStdio));
                continue;
            }
            let Some(command) = entry.get("command").and_then(|v| v.as_str()) else {
                self.skipped.push(skip(SkipReason::NoCommand));
                continue;
            };

            self.servers.push(DiscoveredServer {
                name: name.clone(),
                command: command.to_string(),
                args: entry
                    .get("args")
                    .and_then(|v| v.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|v| v.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default(),
                source: source.to_string(),
            });
        }
        Ok(())
    }
}

/// Where the supported clients keep their MCP configuration.
///
/// Returned as candidates rather than read here: the caller reports which ones
/// existed, and a missing file is normal rather than an error.
///
/// - **Claude Desktop** — macOS `~/Library/Application Support/Claude/`,
///   Linux `~/.config/Claude/`, Windows `%APPDATA%\Claude\`, file
///   `claude_desktop_config.json`.
/// - **Cursor** — `~/.cursor/mcp.json`, plus a project-local `.cursor/mcp.json`
///   in the working directory.
pub fn candidate_paths() -> Vec<PathBuf> {
    let mut paths = Vec::new();

    if let Some(home) = home_dir() {
        if cfg!(target_os = "macos") {
            paths.push(home.join("Library/Application Support/Claude/claude_desktop_config.json"));
        } else {
            paths.push(home.join(".config/Claude/claude_desktop_config.json"));
        }
        paths.push(home.join(".cursor/mcp.json"));
    }
    if let Some(appdata) = std::env::var_os("APPDATA") {
        paths.push(PathBuf::from(appdata).join("Claude/claude_desktop_config.json"));
    }
    // Project-local Cursor config, for a repo that pins its own servers.
    paths.push(PathBuf::from(".cursor/mcp.json"));
    paths
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Render a `customhouse.toml`.
///
/// The output is meant to be read and edited, not just parsed: the comments
/// carry the two decisions a user has to make (which servers are trusted, and
/// which fields carry authorship) and what each one costs.
pub fn render_toml(discovery: &Discovery) -> String {
    let mut out = String::new();
    out.push_str(
        "# Generated by `customhouse init` from the MCP servers your agent client\n\
         # already launches. Review it before serving — this file is policy.\n\n",
    );

    if discovery.servers.is_empty() {
        out.push_str(
            "# No stdio MCP servers were found. Add one per `[[upstream]]` table:\n\
             #\n\
             #   [[upstream]]\n\
             #   name = \"web\"\n\
             #   command = \"npx\"\n\
             #   args = [\"-y\", \"@modelcontextprotocol/server-web\"]\n\n",
        );
    }

    out.push_str(
        "# Every upstream below is UNTRUSTED, because that is the default and\n\
         # `init` never asserts otherwise. An untrusted server's results taint the\n\
         # session, and sink calls are then refused for the rest of it.\n\
         #\n\
         # If a server only ever returns content you control, mark it trusted:\n\
         #\n\
         #   trust = \"trusted\"\n\
         #\n\
         # That is the one line that decides whether a flow is enforced, so make it\n\
         # deliberately. A server that reads the web, a shared inbox, a ticket\n\
         # queue or a file another process writes is not trusted, however\n\
         # reputable its publisher: the question is who can put bytes in its\n\
         # output, not who wrote its code.\n\n",
    );

    for server in &discovery.servers {
        out.push_str("[[upstream]]\n");
        out.push_str(&format!("name = {}\n", toml_string(&server.name)));
        out.push_str(&format!("command = {}\n", toml_string(&server.command)));
        if !server.args.is_empty() {
            let args: Vec<String> = server.args.iter().map(|a| toml_string(a)).collect();
            out.push_str(&format!("args = [{}]\n", args.join(", ")));
        }
        out.push_str(&format!("# from {}\n", server.source));
        out.push_str(
            "# trust is omitted, so this server is untrusted.\n\
             # If its results assert who wrote them, naming the field lets a reply\n\
             # to that author through (see SECURITY.md for the limit):\n\
             #   author_field = \"from\"\n\
             #   recipient_fields = [\"to\", \"cc\", \"bcc\"]\n\n",
        );
    }

    out.push_str(
        "# Enforcement mode per sink class. These are the modes the published\n\
         # false-positive rate in METRICS.md was measured under, not the built-in\n\
         # defaults: the code defaults every class to `deny`, and `init` writes\n\
         # `require_approval` for the two classes where measured false positives\n\
         # made a hard block impractical. `require_approval` still refuses the\n\
         # call — it also tells you what to run to allow one retry.\n\
         #\n\
         # Tighten any line to \"deny\" to drop the escape hatch.\n\
         [flow]\n\
         payment_transfer = \"deny\"\n\
         external_send = \"require_approval\"\n\
         data_egress = \"require_approval\"\n",
    );
    out
}

/// Quote a value as a TOML basic string.
///
/// Written out rather than pulled from a serializer because the emitted file is
/// hand-shaped: comments interleaved with tables, in a fixed order. A serializer
/// would produce valid TOML and drop every comment, which is most of the value
/// here. The round-trip test parses the result back through `Config` so this
/// cannot drift into producing something the loader rejects.
fn toml_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// Why `init` could not produce a config.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    #[error("{path}: not valid JSON: {source}")]
    Parse {
        path: String,
        #[source]
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, TrustClass};
    use crate::sink::SinkClass;

    fn claude_desktop() -> &'static str {
        r#"{
          "mcpServers": {
            "filesystem": {
              "command": "npx",
              "args": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
            },
            "web": { "command": "web-fetch" }
          }
        }"#
    }

    #[test]
    fn reads_the_claude_desktop_shape() {
        let mut d = Discovery::default();
        d.absorb("claude_desktop_config.json", claude_desktop())
            .unwrap();

        assert_eq!(d.servers.len(), 2);
        let fs = d.servers.iter().find(|s| s.name == "filesystem").unwrap();
        assert_eq!(fs.command, "npx");
        assert_eq!(fs.args.len(), 3);
        assert!(d.skipped.is_empty());
    }

    // THE RULE THAT MUST NOT DRIFT. `init` writes policy; if it ever emits a
    // trusted upstream, a user gets enforcement they never agreed to and the
    // failure is silent, because a trusted server simply never taints anything.
    #[test]
    fn generated_config_never_marks_any_upstream_trusted() {
        let mut d = Discovery::default();
        d.absorb("claude_desktop_config.json", claude_desktop())
            .unwrap();
        let rendered = render_toml(&d);

        let config = Config::from_toml_str(&rendered).expect("emitted config must parse");
        assert_eq!(config.upstreams.len(), 2);
        for upstream in &config.upstreams {
            assert_eq!(
                upstream.trust,
                TrustClass::Untrusted,
                "`{}` must be untrusted",
                upstream.name
            );
        }
        // Not merely absent from the parsed struct — absent from the text, so a
        // future template edit that hard-codes it is caught here too.
        let uncommented: String = rendered
            .lines()
            .filter(|l| !l.trim_start().starts_with('#'))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !uncommented.contains("trusted"),
            "no uncommented line may assert trust"
        );
    }

    #[test]
    fn emitted_config_round_trips_through_the_real_loader() {
        // The generator writes TOML by hand, so the loader is the only authority
        // on whether it is valid. `deny_unknown_fields` means a stray key fails
        // here rather than at a user's first `serve`.
        let mut d = Discovery::default();
        d.absorb("claude_desktop_config.json", claude_desktop())
            .unwrap();
        let config = Config::from_toml_str(&render_toml(&d)).unwrap();

        assert_eq!(config.upstreams[0].name, "filesystem");
        assert_eq!(config.upstreams[0].command, "npx");
        assert_eq!(
            config.upstreams[0].args,
            ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"]
        );
    }

    #[test]
    fn an_empty_discovery_still_emits_a_valid_config() {
        let rendered = render_toml(&Discovery::default());
        let config = Config::from_toml_str(&rendered).unwrap();
        assert!(config.upstreams.is_empty());
        assert!(rendered.contains("[[upstream]]"), "shows the shape to add");
    }

    #[test]
    fn emitted_flow_modes_are_the_ones_metrics_was_measured_under() {
        use crate::config::SinkMode;
        let config = Config::from_toml_str(&render_toml(&Discovery::default())).unwrap();
        assert_eq!(
            config.flow.mode_for(SinkClass::PaymentTransfer),
            SinkMode::Deny
        );
        assert_eq!(
            config.flow.mode_for(SinkClass::ExternalSend),
            SinkMode::RequireApproval
        );
        assert_eq!(
            config.flow.mode_for(SinkClass::DataEgress),
            SinkMode::RequireApproval
        );
    }

    #[test]
    fn remote_servers_are_skipped_and_named_rather_than_dropped() {
        let mut d = Discovery::default();
        d.absorb(
            "mcp.json",
            r#"{"mcpServers": {
                 "remote": {"url": "https://example.com/sse"},
                 "typed":  {"type": "http", "url": "https://example.com"},
                 "broken": {"args": ["--stdio"]}
               }}"#,
        )
        .unwrap();

        assert!(d.servers.is_empty(), "none of these can be launched");
        let reasons: Vec<_> = d
            .skipped
            .iter()
            .map(|s| (s.name.as_str(), s.reason))
            .collect();
        assert!(reasons.contains(&("remote", SkipReason::NotStdio)));
        assert!(reasons.contains(&("typed", SkipReason::NotStdio)));
        assert!(reasons.contains(&("broken", SkipReason::NoCommand)));
    }

    #[test]
    fn a_server_in_two_clients_is_written_once() {
        let mut d = Discovery::default();
        d.absorb("claude_desktop_config.json", claude_desktop())
            .unwrap();
        d.absorb(
            "cursor/mcp.json",
            r#"{"mcpServers": {"web": {"command": "somewhere-else"}}}"#,
        )
        .unwrap();

        assert_eq!(d.servers.iter().filter(|s| s.name == "web").count(), 1);
        let dup = d.skipped.iter().find(|s| s.name == "web").unwrap();
        assert_eq!(dup.reason, SkipReason::DuplicateName);
        assert_eq!(
            d.servers.iter().find(|s| s.name == "web").unwrap().command,
            "web-fetch",
            "first config read wins, so the result is order-stable"
        );
    }

    #[test]
    fn a_name_that_would_break_namespacing_is_refused() {
        let mut d = Discovery::default();
        d.absorb(
            "mcp.json",
            r#"{"mcpServers": {"we__b": {"command": "x"}, "": {"command": "y"}}}"#,
        )
        .unwrap();
        assert!(d.servers.is_empty());
        assert!(d
            .skipped
            .iter()
            .all(|s| s.reason == SkipReason::UnusableName));
    }

    #[test]
    fn a_config_with_no_mcp_servers_key_is_not_an_error() {
        let mut d = Discovery::default();
        d.absorb("settings.json", r#"{"theme": "dark"}"#).unwrap();
        assert!(d.is_empty());
    }

    #[test]
    fn malformed_json_names_the_file_it_came_from() {
        let mut d = Discovery::default();
        let err = d.absorb("cursor/mcp.json", "{not json").unwrap_err();
        assert!(
            err.to_string().contains("cursor/mcp.json"),
            "the message must say which file to fix, got: {err}"
        );
    }

    #[test]
    fn quoting_survives_a_command_with_awkward_characters() {
        let mut d = Discovery::default();
        d.absorb(
            "mcp.json",
            r#"{"mcpServers": {"odd": {"command": "C:\\Program Files\\a b\\srv.exe",
               "args": ["--say=\"hi\""]}}}"#,
        )
        .unwrap();

        let config = Config::from_toml_str(&render_toml(&d)).unwrap();
        assert_eq!(
            config.upstreams[0].command,
            "C:\\Program Files\\a b\\srv.exe"
        );
        assert_eq!(config.upstreams[0].args, ["--say=\"hi\""]);
    }
}

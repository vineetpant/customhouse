//! Upstream MCP servers and the registry that aggregates them.
//!
//! Customhouse spawns each configured upstream, connects as an MCP client over the
//! child's stdio, and merges their tools into one namespaced set. Tool calls
//! from the client are routed back to the owning upstream under the tool's
//! original name. Upstream errors are wrapped, never swallowed.

use std::borrow::Cow;
use std::collections::HashMap;

use rmcp::{
    model::{CallToolRequestParams, CallToolResult, Tool},
    service::{RunningService, ServiceError},
    transport::TokioChildProcess,
    RoleClient, ServiceExt,
};

use crate::config::{TrustClass, UpstreamConfig, NAMESPACE_SEP};
use crate::pin::{CheckedTool, PinOutcome, PinStore};

/// The client-namespaced identifier for a tool, e.g. `web` + `fetch` →
/// `web__fetch`.
pub fn namespaced_tool_name(server: &str, tool: &str) -> String {
    format!("{server}{NAMESPACE_SEP}{tool}")
}

/// A live connection to one upstream MCP server.
pub struct Upstream {
    name: String,
    service: RunningService<RoleClient, ()>,
}

impl Upstream {
    /// Spawn the configured command and complete the MCP handshake as a client.
    pub async fn connect(config: &UpstreamConfig) -> Result<Self, UpstreamError> {
        let mut command = tokio::process::Command::new(&config.command);
        command.args(&config.args);
        let transport = TokioChildProcess::new(command).map_err(UpstreamError::Spawn)?;
        let service = ().serve(transport).await.map_err(UpstreamError::connect)?;
        Ok(Self {
            name: config.name.clone(),
            service,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    /// The upstream's declared implementation version, from its initialize
    /// handshake. Pins are bound to it (§4): a version change invalidates them.
    pub fn declared_version(&self) -> Option<String> {
        self.service
            .peer_info()
            .map(|info| info.server_info.version.clone())
    }

    /// Every tool this upstream advertises, under its own (un-namespaced) names.
    pub async fn list_tools(&self) -> Result<Vec<Tool>, ServiceError> {
        self.service.list_all_tools().await
    }

    /// Invoke a tool on this upstream by its original name.
    pub async fn call_tool(
        &self,
        params: CallToolRequestParams,
    ) -> Result<CallToolResult, ServiceError> {
        self.service.call_tool(params).await
    }
}

/// Where a namespaced tool name routes to: the owning upstream (by index, for
/// the live connection) under its original, un-namespaced name.
struct Route {
    upstream_index: usize,
    original_name: String,
    server: String,
}

/// The aggregated view of all upstreams: the merged tool list Customhouse exposes
/// and the routing table that maps each namespaced tool back to its owner.
#[derive(Default)]
pub struct Registry {
    upstreams: Vec<Upstream>,
    tools: Vec<Tool>,
    routes: HashMap<String, Route>,
    /// Trust class per upstream name. Absent means untrusted: a server we do
    /// not know about cannot be assumed clean.
    trust: HashMap<String, TrustClass>,
}

impl Registry {
    /// An empty registry, aggregating nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Connect every configured upstream, pin-check its tools, and build the
    /// merged set from the *served* tools only.
    ///
    /// Fails closed: if any upstream cannot be reached, or two upstreams would
    /// produce the same namespaced tool name, the whole build fails rather than
    /// serving a partial or ambiguous surface. Metadata events (pins, withholds)
    /// are returned for the caller to record; the registry stays ledger-free.
    pub async fn connect(
        configs: &[UpstreamConfig],
        pins: &mut PinStore,
    ) -> Result<(Self, Vec<MetadataEvent>), UpstreamError> {
        let mut registry = Registry::empty();
        let mut events = Vec::new();
        for config in configs {
            let upstream = Upstream::connect(config).await?;
            let index = registry.upstreams.len();
            let tools = upstream
                .list_tools()
                .await
                .map_err(|source| UpstreamError::ListTools {
                    upstream: config.name.clone(),
                    source,
                })?;
            registry.trust.insert(config.name.clone(), config.trust);
            let version = upstream.declared_version();
            let checked = pins.check_server(&config.name, version.as_deref(), tools);
            events.extend(registry.apply_server_checks(&config.name, index, checked)?);
            registry.upstreams.push(upstream);
        }
        if let Err(e) = pins.save() {
            // Fail-safe, not fail-closed: if pins can't persist, next run re-pins
            // first-sight (it will not wrongly serve a mutated definition), but
            // rug-pull detection is degraded until the store is writable again.
            eprintln!(
                "customhouse: failed to persist pin store (detection degraded next run): {e}"
            );
        }
        Ok((registry, events))
    }

    /// Insert the served tools (first-sight / unchanged) into the merged set and
    /// collect a [`MetadataEvent`] for each pin and each withhold. Withheld tools
    /// are never inserted — Customhouse does not serve a pinned definition while the
    /// upstream would execute the new one.
    ///
    /// Each tool arrives already carrying its own verdict, so there is no way to
    /// gate one tool with another's outcome.
    fn apply_server_checks(
        &mut self,
        server: &str,
        index: usize,
        checked: Vec<CheckedTool>,
    ) -> Result<Vec<MetadataEvent>, UpstreamError> {
        let mut events = Vec::new();
        for CheckedTool { tool, outcome } in checked {
            let tool_name = tool.name.to_string();
            if outcome.is_served() {
                // First sight is worth recording; an unchanged tool is not.
                if matches!(outcome, PinOutcome::FirstSight) {
                    events.push(MetadataEvent::new(server, tool_name, outcome));
                }
                self.insert_tool(server, index, tool)?;
            } else {
                events.push(MetadataEvent::new(server, tool_name, outcome));
            }
        }
        Ok(events)
    }

    fn insert_tool(
        &mut self,
        server: &str,
        upstream_index: usize,
        tool: Tool,
    ) -> Result<(), UpstreamError> {
        let qualified = namespaced_tool_name(server, &tool.name);
        if self.routes.contains_key(&qualified) {
            return Err(UpstreamError::ToolNameCollision(qualified));
        }
        let original_name = tool.name.to_string();
        let mut namespaced = tool;
        namespaced.name = Cow::Owned(qualified.clone());
        self.routes.insert(
            qualified,
            Route {
                upstream_index,
                original_name,
                server: server.to_string(),
            },
        );
        self.tools.push(namespaced);
        Ok(())
    }

    /// The merged, namespaced tool list to advertise to the client.
    pub fn tools(&self) -> &[Tool] {
        &self.tools
    }

    /// The upstream that owns a namespaced tool, if Customhouse exposes it. Lets
    /// callers recover the server structurally instead of re-parsing the name.
    pub fn server_of(&self, namespaced_tool: &str) -> Option<&str> {
        self.routes.get(namespaced_tool).map(|r| r.server.as_str())
    }

    /// The trust class of an upstream. Unknown servers are untrusted — the
    /// default-deny attribution the taint model rests on (§7.1).
    pub fn trust_of(&self, server: &str) -> TrustClass {
        self.trust.get(server).copied().unwrap_or_default()
    }

    /// Route a client tool call to its owning upstream, rewriting the namespaced
    /// name back to the upstream's original name.
    pub async fn route_call(
        &self,
        request: CallToolRequestParams,
    ) -> Result<CallToolResult, CallError> {
        let route =
            self.routes
                .get(request.name.as_ref())
                .ok_or_else(|| CallError::UnknownTool {
                    tool: request.name.to_string(),
                })?;
        let upstream = &self.upstreams[route.upstream_index];

        // Rewrite the namespaced name back to the upstream's own name, carrying
        // the caller's arguments through unchanged.
        let params = match request.arguments {
            Some(arguments) => {
                CallToolRequestParams::new(route.original_name.clone()).with_arguments(arguments)
            }
            None => CallToolRequestParams::new(route.original_name.clone()),
        };

        upstream
            .call_tool(params)
            .await
            .map_err(|source| CallError::Upstream {
                upstream: upstream.name().to_string(),
                source,
            })
    }
}

/// Failures while connecting an upstream and building the registry. Every
/// variant names the upstream so a wrapped error never loses which server failed.
#[derive(Debug, thiserror::Error)]
pub enum UpstreamError {
    #[error("failed to spawn upstream process: {0}")]
    Spawn(#[source] std::io::Error),
    #[error("failed to connect to upstream: {0}")]
    Connect(String),
    #[error("upstream `{upstream}` failed to list tools: {source}")]
    ListTools {
        upstream: String,
        #[source]
        source: ServiceError,
    },
    #[error("two upstreams both expose the tool `{0}`")]
    ToolNameCollision(String),
}

impl UpstreamError {
    fn connect(error: impl std::fmt::Display) -> Self {
        UpstreamError::Connect(error.to_string())
    }
}

/// A metadata-pinning event from building the registry: a tool pinned at first
/// sight, or a tool withheld because its definition or its server's version
/// changed. Returned by [`Registry::connect`] for the caller to record and
/// surface; carries the pin outcome (including the before/after diff on a
/// mutation) so the ledger and operator get the full picture.
#[derive(Debug, Clone)]
pub struct MetadataEvent {
    pub server: String,
    pub tool: String,
    pub outcome: PinOutcome,
}

impl MetadataEvent {
    fn new(server: &str, tool: String, outcome: PinOutcome) -> Self {
        Self {
            server: server.to_string(),
            tool,
            outcome,
        }
    }

    /// The client-facing namespaced name this event concerns.
    pub fn qualified_tool(&self) -> String {
        namespaced_tool_name(&self.server, &self.tool)
    }

    /// A one-line operator summary, or `None` when there is nothing to say (an
    /// unchanged tool). Pure: the caller decides where it is written.
    pub fn summary(&self) -> Option<String> {
        let tool = self.qualified_tool();
        match &self.outcome {
            PinOutcome::FirstSight => Some(format!("pinned {tool}")),
            PinOutcome::Mutated { .. } => Some(format!(
                "WITHHELD {tool} — definition changed since pinned; run `customhouse repin {}` to accept",
                self.server,
            )),
            PinOutcome::VersionChanged {
                pinned_version,
                current_version,
            } => Some(format!(
                "WITHHELD {tool} — upstream version changed {pinned_version:?} -> {current_version:?}; run `customhouse repin {}`",
                self.server,
            )),
            PinOutcome::Unchanged => None,
        }
    }
}

/// Failures routing or executing a client tool call. Distinct from build-time
/// [`UpstreamError`]: these are the outcomes the proxy maps to MCP errors.
#[derive(Debug, thiserror::Error)]
pub enum CallError {
    #[error("no upstream exposes tool `{tool}`")]
    UnknownTool { tool: String },
    #[error("upstream `{upstream}` failed to run tool: {source}")]
    Upstream {
        upstream: String,
        #[source]
        source: ServiceError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_tool_names() {
        assert_eq!(namespaced_tool_name("web", "fetch"), "web__fetch");
    }

    #[test]
    fn namespace_splits_on_first_separator_only() {
        // A tool whose own name contains the separator still resolves to the
        // right upstream, because the upstream name never contains it.
        let qualified = namespaced_tool_name("web", "sub__tool");
        assert_eq!(
            qualified.split_once(NAMESPACE_SEP),
            Some(("web", "sub__tool"))
        );
    }

    fn tool(name: &str) -> Tool {
        Tool::new(
            name.to_string(),
            "test tool",
            std::sync::Arc::new(serde_json::Map::new()),
        )
    }

    #[test]
    fn merges_and_namespaces_tools() {
        let mut registry = Registry::empty();
        registry.insert_tool("web", 0, tool("fetch")).unwrap();
        registry.insert_tool("mail", 1, tool("send")).unwrap();

        let names: Vec<_> = registry.tools().iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(names, ["web__fetch", "mail__send"]);
    }

    #[test]
    fn detects_tool_name_collisions() {
        let mut registry = Registry::empty();
        registry.insert_tool("web", 0, tool("fetch")).unwrap();
        let collision = registry.insert_tool("web", 0, tool("fetch"));
        assert!(matches!(
            collision,
            Err(UpstreamError::ToolNameCollision(_))
        ));
    }

    #[test]
    fn routing_preserves_original_name() {
        let mut registry = Registry::empty();
        registry.insert_tool("web", 0, tool("fetch")).unwrap();
        let route = registry.routes.get("web__fetch").unwrap();
        assert_eq!(route.original_name, "fetch");
        assert_eq!(route.upstream_index, 0);
    }

    #[test]
    fn server_of_resolves_owner_structurally() {
        let mut registry = Registry::empty();
        registry.insert_tool("web", 0, tool("fetch")).unwrap();
        assert_eq!(registry.server_of("web__fetch"), Some("web"));
        assert_eq!(registry.server_of("mail__send"), None);
    }

    #[tokio::test]
    async fn routing_an_unknown_tool_is_a_typed_error() {
        let registry = Registry::empty();
        let request = CallToolRequestParams::new("web__fetch");
        let error = registry.route_call(request).await.unwrap_err();
        assert!(matches!(error, CallError::UnknownTool { tool } if tool == "web__fetch"));
    }

    fn check(name: &str, outcome: PinOutcome) -> CheckedTool {
        CheckedTool {
            tool: tool(name),
            outcome,
        }
    }

    #[test]
    fn withheld_tools_are_not_served_but_are_reported() {
        let mut registry = Registry::empty();
        let checked = vec![
            check("fetch", PinOutcome::FirstSight),
            check(
                "send",
                PinOutcome::Mutated {
                    pinned: "old".into(),
                    current: "new".into(),
                },
            ),
        ];
        let events = registry.apply_server_checks("web", 0, checked).unwrap();

        // Only the served (first-sight) tool reaches the merged set; the mutated
        // one is withheld — never served under its pinned definition.
        let names: Vec<_> = registry.tools().iter().map(|t| t.name.as_ref()).collect();
        assert_eq!(names, ["web__fetch"]);
        assert_eq!(registry.server_of("web__send"), None);

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].qualified_tool(), "web__fetch");
        assert!(matches!(events[0].outcome, PinOutcome::FirstSight));
        assert_eq!(events[1].qualified_tool(), "web__send");
        assert!(matches!(events[1].outcome, PinOutcome::Mutated { .. }));
    }

    #[test]
    fn unchanged_tools_are_served_without_an_event() {
        let mut registry = Registry::empty();
        let events = registry
            .apply_server_checks("web", 0, vec![check("fetch", PinOutcome::Unchanged)])
            .unwrap();
        assert_eq!(registry.tools().len(), 1);
        assert!(events.is_empty());
    }

    #[test]
    fn summary_is_pure_and_silent_for_unchanged() {
        let withheld = MetadataEvent::new(
            "web",
            "send".to_string(),
            PinOutcome::Mutated {
                pinned: "old".into(),
                current: "new".into(),
            },
        );
        let summary = withheld.summary().expect("a withhold has a summary");
        assert!(summary.contains("WITHHELD web__send"));
        assert!(summary.contains("customhouse repin web"));

        let unchanged = MetadataEvent::new("web", "fetch".to_string(), PinOutcome::Unchanged);
        assert!(
            unchanged.summary().is_none(),
            "nothing to say for unchanged"
        );
    }
}

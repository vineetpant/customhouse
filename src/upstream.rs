//! Upstream MCP servers and the registry that aggregates them.
//!
//! Bulkhead spawns each configured upstream, connects as an MCP client over the
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

use crate::config::{UpstreamConfig, NAMESPACE_SEP};

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

/// The aggregated view of all upstreams: the merged tool list Bulkhead exposes
/// and the routing table that maps each namespaced tool back to its owner.
#[derive(Default)]
pub struct Registry {
    upstreams: Vec<Upstream>,
    tools: Vec<Tool>,
    routes: HashMap<String, Route>,
}

impl Registry {
    /// An empty registry, aggregating nothing.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Connect every configured upstream and build the merged tool set.
    ///
    /// Fails closed: if any upstream cannot be reached, or two upstreams would
    /// produce the same namespaced tool name, the whole build fails rather than
    /// serving a partial or ambiguous surface.
    pub async fn connect(configs: &[UpstreamConfig]) -> Result<Self, UpstreamError> {
        let mut registry = Registry::empty();
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
            for tool in tools {
                registry.insert_tool(&config.name, index, tool)?;
            }
            registry.upstreams.push(upstream);
        }
        Ok(registry)
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

    /// The upstream that owns a namespaced tool, if Bulkhead exposes it. Lets
    /// callers recover the server structurally instead of re-parsing the name.
    pub fn server_of(&self, namespaced_tool: &str) -> Option<&str> {
        self.routes.get(namespaced_tool).map(|r| r.server.as_str())
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
}

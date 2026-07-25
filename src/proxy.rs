//! The aggregating MCP proxy.
//!
//! `BulkheadProxy` presents Bulkhead to the client as a single MCP server that
//! exposes the merged, namespaced tools of its upstream servers and routes each
//! call back to the owning upstream. Policy is not yet enforced here — the proxy
//! passes calls through — but this is the single chokepoint every future
//! decision runs at.

use std::sync::Arc;

use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo,
    },
    service::RequestContext,
    transport::stdio,
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};

use crate::config::Config;
use crate::upstream::{Registry, UpstreamError};

/// Bulkhead presented to the client as a single aggregating MCP server.
///
/// Cheap to clone: the shared registry of upstream connections lives behind an
/// `Arc`, so the proxy can be handed to the MCP service by value.
#[derive(Clone)]
pub struct BulkheadProxy {
    registry: Arc<Registry>,
}

impl BulkheadProxy {
    /// A proxy with no upstreams; advertises an empty tool set.
    pub fn empty() -> Self {
        Self {
            registry: Arc::new(Registry::empty()),
        }
    }

    /// Connect every upstream in `config` and build the aggregated proxy.
    pub async fn connect(config: &Config) -> Result<Self, UpstreamError> {
        let registry = Registry::connect(&config.upstreams).await?;
        Ok(Self {
            registry: Arc::new(registry),
        })
    }

    /// Number of tools currently exposed to the client.
    pub fn tool_count(&self) -> usize {
        self.registry.tools().len()
    }

    /// The identity Bulkhead presents to clients on initialize.
    pub fn server_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            // MCP 2025-11-25 (ProtocolVersion::LATEST in rmcp 2.2.0).
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new("bulkhead", crate::version()))
            .with_instructions("Bulkhead: a deterministic proxy over your MCP servers.")
    }
}

impl ServerHandler for BulkheadProxy {
    fn get_info(&self) -> ServerInfo {
        self.server_info()
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(
            self.registry.tools().to_vec(),
        ))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let tool = request.name.clone();
        match self.registry.route_call(request).await {
            Some(Ok(result)) => Ok(result),
            // Wrap the upstream failure so its origin is preserved, not swallowed.
            Some(Err(error)) => Err(McpError::internal_error(error.to_string(), None)),
            None => Err(McpError::invalid_params(
                format!("no upstream exposes tool `{tool}`"),
                None,
            )),
        }
    }
}

/// Serve Bulkhead as an MCP server over stdio until the client disconnects.
///
/// stdout carries the MCP protocol; all logging must go to stderr.
pub async fn serve_stdio(config: Config) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let proxy = BulkheadProxy::connect(&config).await?;
    eprintln!(
        "bulkhead {}: aggregating {} upstream(s), exposing {} tool(s)",
        crate::version(),
        config.upstreams.len(),
        proxy.tool_count(),
    );
    let running = proxy.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presents_as_bulkhead() {
        let info = BulkheadProxy::empty().server_info();
        assert_eq!(info.server_info.name, "bulkhead");
        assert_eq!(info.server_info.version, crate::version());
    }

    #[test]
    fn negotiates_supported_protocol_version() {
        let info = BulkheadProxy::empty().server_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
    }

    #[test]
    fn advertises_tools_capability() {
        let info = BulkheadProxy::empty().server_info();
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn empty_proxy_exposes_no_tools() {
        assert_eq!(BulkheadProxy::empty().tool_count(), 0);
    }
}

//! The aggregating MCP proxy.
//!
//! Chunk 1: a valid MCP stdio server that presents Bulkhead as a single server
//! and exposes an (empty) aggregated tool list. Upstream connection and
//! namespacing land in chunk 2; policy stays hardwired to allow through Phase 0.

use rmcp::{
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
    model::{
        CallToolRequestParams, CallToolResult, Implementation, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
    transport::stdio,
};

/// Bulkhead presented to the client as a single aggregating MCP server.
#[derive(Debug, Default, Clone)]
pub struct BulkheadProxy {
    // Upstream servers and their namespaced tools land here in chunk 2.
}

impl BulkheadProxy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every tool Bulkhead exposes to the client, already namespaced by
    /// upstream (`web__fetch`, ...). Pure and directly unit-testable so the
    /// aggregation logic never needs a live MCP client to verify. Empty until
    /// chunk 2 wires the first upstream.
    pub fn aggregated_tools(&self) -> Vec<Tool> {
        Vec::new()
    }

    /// The identity Bulkhead presents to clients on initialize.
    pub fn server_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            // MCP 2025-11-25 (ProtocolVersion::LATEST in rmcp 2.2.0). 2026-07-28
            // is a migration target once rmcp ships it (see CLAUDE.md).
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new("bulkhead", crate::version()))
            .with_instructions(
                "Bulkhead: deterministic MCP proxy. Phase 0 passthrough; no upstreams wired yet.",
            )
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
        let mut result = ListToolsResult::default();
        result.tools = self.aggregated_tools();
        Ok(result)
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        // No upstreams to route to yet; refuse clearly rather than pretend.
        Err(McpError::invalid_request(
            format!("bulkhead: no upstream provides tool `{}` (chunk 1)", request.name),
            None,
        ))
    }
}

/// Serve Bulkhead as an MCP server over stdio until the client disconnects.
///
/// stdout carries the MCP protocol; all logging must go to stderr.
pub async fn serve_stdio() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let proxy = BulkheadProxy::new();
    let running = proxy.serve(stdio()).await?;
    running.waiting().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presents_as_bulkhead() {
        let info = BulkheadProxy::new().server_info();
        assert_eq!(info.server_info.name, "bulkhead");
        assert_eq!(info.server_info.version, crate::version());
    }

    #[test]
    fn negotiates_supported_protocol_version() {
        let info = BulkheadProxy::new().server_info();
        // Pinned rmcp 2.2.0 speaks MCP 2025-11-25.
        assert_eq!(info.protocol_version, ProtocolVersion::V_2025_11_25);
    }

    #[test]
    fn advertises_tools_capability() {
        let info = BulkheadProxy::new().server_info();
        assert!(info.capabilities.tools.is_some(), "must advertise tools capability");
    }

    #[test]
    fn exposes_no_tools_before_upstreams() {
        assert!(BulkheadProxy::new().aggregated_tools().is_empty());
    }

    #[test]
    fn get_info_matches_server_info() {
        let proxy = BulkheadProxy::new();
        assert_eq!(proxy.get_info().server_info.name, proxy.server_info().server_info.name);
    }
}

//! A minimal upstream MCP server used as a test fixture.
//!
//! It exposes a single `echo` tool that returns its `text` argument. Bulkhead
//! spawns it to exercise upstream aggregation and call routing end to end,
//! without depending on any external server or the network.

use std::sync::Arc;

use rmcp::{
    model::{
        CallToolRequestParams, CallToolResult, ContentBlock, Implementation, ListToolsResult,
        PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool,
    },
    service::RequestContext,
    transport::stdio,
    ErrorData as McpError, RoleServer, ServerHandler, ServiceExt,
};

#[derive(Clone)]
struct MockUpstream;

impl MockUpstream {
    fn echo_tool() -> Tool {
        let schema = serde_json::json!({
            "type": "object",
            "properties": { "text": { "type": "string" } },
            "required": ["text"],
        });
        let input_schema = Arc::new(schema.as_object().expect("schema is an object").clone());
        Tool::new(
            "echo",
            "Echo the `text` argument back to the caller.",
            input_schema,
        )
    }
}

impl ServerHandler for MockUpstream {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new(
                "mock-upstream",
                env!("CARGO_PKG_VERSION"),
            ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(vec![Self::echo_tool()]))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        if request.name != "echo" {
            return Err(McpError::invalid_params(
                format!("unknown tool `{}`", request.name),
                None,
            ));
        }
        let text = request
            .arguments
            .as_ref()
            .and_then(|args| args.get("text"))
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        Ok(CallToolResult::success(vec![ContentBlock::text(text)]))
    }
}

fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mock-upstream: failed to start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };

    let result = runtime.block_on(async {
        let running = MockUpstream.serve(stdio()).await?;
        running.waiting().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mock-upstream: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

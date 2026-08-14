//! A minimal MCP server exposing sink tools, used as the *destination* half of
//! the flow demos.
//!
//! It exposes `send_email` and `transfer_funds` — an external send and a money
//! movement. Both simply report what they would have done: the point of the
//! demo is whether Customhouse lets the call through at all, so the tool doing
//! nothing real is a feature.
//!
//! The taint *source* in the demos is a real MCP server; only this sink side is
//! mocked, because no one should need a payment provider to run a demo.

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
struct MockSink;

impl MockSink {
    fn tools() -> Vec<Tool> {
        let recipient = serde_json::json!({
            "type": "object",
            "properties": { "to": { "type": "string" }, "body": { "type": "string" } },
            "required": ["to"],
        });
        let transfer = serde_json::json!({
            "type": "object",
            "properties": { "to": { "type": "string" }, "amount": { "type": "number" } },
            "required": ["to", "amount"],
        });
        vec![
            Tool::new(
                "send_email",
                "Send an email to a recipient.",
                Arc::new(recipient.as_object().expect("object").clone()),
            ),
            Tool::new(
                "transfer_funds",
                "Transfer money to an account.",
                Arc::new(transfer.as_object().expect("object").clone()),
            ),
        ]
    }
}

impl ServerHandler for MockSink {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_protocol_version(ProtocolVersion::LATEST)
            .with_server_info(Implementation::new("mock-sink", env!("CARGO_PKG_VERSION")))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult::with_all_items(Self::tools()))
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        _context: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, McpError> {
        let args = request.arguments.unwrap_or_default();
        let to = args
            .get("to")
            .and_then(|v| v.as_str())
            .unwrap_or("<nobody>");
        let reply = match request.name.as_ref() {
            "send_email" => format!("EMAIL SENT to {to}"),
            "transfer_funds" => {
                let amount = args.get("amount").and_then(|v| v.as_f64()).unwrap_or(0.0);
                format!("TRANSFERRED {amount} to {to}")
            }
            other => {
                return Err(McpError::invalid_params(
                    format!("unknown tool `{other}`"),
                    None,
                ))
            }
        };
        Ok(CallToolResult::success(vec![ContentBlock::text(reply)]))
    }
}

fn main() -> std::process::ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("mock-sink: failed to start runtime: {e}");
            return std::process::ExitCode::FAILURE;
        }
    };
    let result = runtime.block_on(async {
        let running = MockSink.serve(stdio()).await?;
        running.waiting().await?;
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    });
    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mock-sink: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

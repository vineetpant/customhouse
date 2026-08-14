//! Self-protection proven against a *real* MCP server, not the bundled mock.
//!
//! Run through `./demo/run_selfprotect_real.sh`, which needs Node (it fetches
//! the official `@modelcontextprotocol/server-filesystem` via npx).
//!
//! The setup is deliberately hostile to Customhouse: `CUSTOMHOUSE_HOME` is placed
//! *inside* the directory the filesystem server is allowed to access, so the
//! server is fully capable of reading the ledger and overwriting the pin store.
//! Nothing but the §3 invariant gate stands between the agent and Customhouse's own
//! state. Every outcome below is asserted — if self-protection regressed, this
//! exits non-zero instead of printing something reassuring.

use std::error::Error;

use rmcp::{
    model::CallToolRequestParams, service::ServiceError, transport::TokioChildProcess, ServiceExt,
};

type BoxError = Box<dyn Error + Send + Sync>;
type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let bin = env_or("CUSTOMHOUSE_BIN", "target/release/customhouse");
    let config = env_or("CUSTOMHOUSE_CONFIG", "");
    let home = std::env::var("CUSTOMHOUSE_HOME").expect("run via ./demo/run_selfprotect_real.sh");
    let safe_file = std::env::var("CUSTOMHOUSE_DEMO_FILE").expect("run via the demo script");

    rule("Customhouse vs a real MCP server (@modelcontextprotocol/server-filesystem)");
    say(&format!(
        "the server is allowed to access the directory that also contains\n  \
         Customhouse's own state: {home}\n  \
         so the server *can* reach these files — only the gate stops it."
    ));

    let mut command = tokio::process::Command::new(&bin);
    command.args(["serve", "--config", &config]);
    let client = ().serve(TokioChildProcess::new(command)?).await?;

    let tools: Vec<String> = client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    say(&format!(
        "{} tools aggregated and pinned from the real server",
        tools.len()
    ));

    // Resolve tool names from what the server actually advertises, so the demo
    // survives upstream renames rather than failing confusingly.
    let read_tool = pick(&tools, &["fs__read_text_file", "fs__read_file"])?;
    let write_tool = pick(&tools, &["fs__write_file"])?;

    rule("ALLOWED: an ordinary file read passes straight through");
    let text = call(&client, &read_tool, "path", &safe_file).await;
    match &text {
        Ok(content) => ok(&format!("{read_tool} -> {:?}", truncate(content))),
        Err(e) => return Err(format!("a normal read should succeed, got: {e}").into()),
    }

    rule("DENIED: the agent tries to read Customhouse's own audit ledger");
    let ledger = format!("{home}/ledger.jsonl");
    assert_denied(&client, &read_tool, "path", &ledger, "read the ledger").await?;

    rule("DENIED: the agent tries to overwrite Customhouse's pin store");
    let pins = format!("{home}/pins.json");
    assert_denied(
        &client,
        &write_tool,
        "path",
        &pins,
        "overwrite the pin store",
    )
    .await?;

    client.cancel().await?;
    println!(
        "\nA real filesystem server, holding real permissions over these files,\n\
         was refused both times — and the refusals are in the ledger it could not read.\n"
    );
    Ok(())
}

/// Call a tool and require that Customhouse refuses it. A success here means
/// self-protection has regressed against real software.
async fn assert_denied(
    client: &Client,
    tool: &str,
    key: &str,
    value: &str,
    what: &str,
) -> Result<(), BoxError> {
    say(value);
    match call(client, tool, key, value).await {
        Ok(content) => Err(format!(
            "SELF-PROTECTION REGRESSED: {what} succeeded, returning {:?}",
            truncate(&content)
        )
        .into()),
        Err(ServiceError::McpError(e)) => {
            blocked(&format!("refused ({}): {}", e.code.0, e.message));
            Ok(())
        }
        Err(other) => Err(format!("unexpected transport failure: {other}").into()),
    }
}

async fn call(client: &Client, tool: &str, key: &str, value: &str) -> Result<String, ServiceError> {
    let mut args = serde_json::Map::new();
    args.insert(key.into(), value.into());
    // `write_file` needs content as well; harmless for readers that ignore it.
    args.insert("content".into(), "overwritten-by-demo".into());
    let result = client
        .call_tool(CallToolRequestParams::new(tool.to_string()).with_arguments(args))
        .await?;
    Ok(result
        .content
        .first()
        .and_then(|b| b.as_text())
        .map(|t| t.text.clone())
        .unwrap_or_default())
}

fn pick(available: &[String], candidates: &[&str]) -> Result<String, BoxError> {
    candidates
        .iter()
        .find(|c| available.iter().any(|a| a == *c))
        .map(|c| c.to_string())
        .ok_or_else(|| {
            format!("none of {candidates:?} found in upstream tools: {available:?}").into()
        })
}

fn truncate(s: &str) -> String {
    s.chars()
        .take(48)
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn rule(title: &str) {
    println!("\n\u{2500}\u{2500} {title} \u{2500}\u{2500}");
}
fn say(detail: &str) {
    println!("  {detail}");
}
fn ok(detail: &str) {
    println!("  \u{2713} {detail}");
}
fn blocked(detail: &str) {
    println!("  \u{2717} {detail}");
}

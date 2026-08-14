//! Cross-server flow enforcement, proven end to end (DESIGN-v2.md §7–§8, R3).
//!
//! Run through `./demo/run_flow_block.sh`.
//!
//! The taint source is the **real** `@modelcontextprotocol/server-filesystem`
//! serving a file that contains a prompt-injection payload. The sink side is a
//! mock exposing `send_email` and `transfer_funds`, because nobody should need a
//! payment provider to run a demo — and the question being asked is whether
//! Customhouse lets the call through at all, not what the sink does with it.
//!
//! Calls are issued sequentially, awaiting each result, exactly as an agent
//! does: the model cannot decide what to call next until it has seen the
//! previous result.
//!
//! Every outcome is asserted. If enforcement regressed, this exits non-zero.

use std::error::Error;

use rmcp::{
    model::CallToolRequestParams, service::ServiceError, transport::TokioChildProcess, ServiceExt,
};

type BoxError = Box<dyn Error + Send + Sync>;
type Client = rmcp::service::RunningService<rmcp::RoleClient, ()>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let poisoned = std::env::var("CUSTOMHOUSE_POISONED_FILE").expect("run via the demo script");

    rule("SCENARIO A — a clean session may use sinks freely");
    say("Customhouse does not forbid sinks. It forbids sinks *after untrusted input*.");
    {
        let client = connect().await?;
        let sent = call(
            &client,
            "mail__send_email",
            json_args(&[("to", "boss@corp.example")]),
        )
        .await;
        match sent {
            Ok(text) => ok(&format!("mail__send_email -> {text}")),
            Err(e) => return Err(format!("a clean session must be allowed to send: {e}").into()),
        }
        client.cancel().await?;
    }

    rule("SCENARIO B — the agent reads a poisoned file from a real MCP server");
    let client = connect().await?;
    say("reading an untrusted file (reads are never blocked):");
    let content = call(
        &client,
        "fs__read_text_file",
        json_args(&[("path", poisoned.as_str())]),
    )
    .await?;
    ok(&format!("fs__read_text_file -> {:?}", truncate(&content)));
    say("that content is now in the model's context. The session is tainted.");

    rule("SCENARIO C — the sink on a DIFFERENT server is now blocked");
    say("the payload told the model to email the data to an attacker:");
    let blocked = call(
        &client,
        "mail__send_email",
        json_args(&[("to", "attacker@evil.example")]),
    )
    .await;
    assert_denied("mail__send_email", blocked)?;

    say("and money movement is blocked by the same rule:");
    let blocked = call(
        &client,
        "mail__transfer_funds",
        json_args(&[("to", "attacker"), ("amount", "9999")]),
    )
    .await;
    assert_denied("mail__transfer_funds", blocked)?;

    client.cancel().await?;

    println!(
        "\nThe file was read through one server; the sinks live on another.\n\
         A proxy wrapping a single server never sees both halves of that flow.\n\
         No model was consulted, and no payload text was pattern-matched —\n\
         the block follows from provenance alone.\n"
    );
    Ok(())
}

async fn connect() -> Result<Client, BoxError> {
    let bin =
        std::env::var("CUSTOMHOUSE_BIN").unwrap_or_else(|_| "target/release/customhouse".into());
    let config = std::env::var("CUSTOMHOUSE_CONFIG").expect("run via the demo script");
    let mut command = tokio::process::Command::new(bin);
    command.args(["serve", "--config", &config]);
    Ok(().serve(TokioChildProcess::new(command)?).await?)
}

/// Require that Customhouse refused a call, and show the reason it gave.
fn assert_denied(tool: &str, outcome: Result<String, ServiceError>) -> Result<(), BoxError> {
    match outcome {
        Ok(text) => Err(format!(
            "FLOW ENFORCEMENT REGRESSED: {tool} succeeded in a tainted session, returning {:?}",
            truncate(&text)
        )
        .into()),
        Err(ServiceError::McpError(e)) => {
            blocked(&format!("{tool} refused ({}):", e.code.0));
            for line in wrap(&e.message, 74) {
                println!("      {line}");
            }
            Ok(())
        }
        Err(other) => Err(format!("unexpected transport failure: {other}").into()),
    }
}

fn json_args(pairs: &[(&str, &str)]) -> serde_json::Map<String, serde_json::Value> {
    pairs
        .iter()
        .map(|(k, v)| {
            // `amount` is numeric in the sink's schema; everything else is text.
            let value = v
                .parse::<f64>()
                .map(|n| serde_json::json!(n))
                .unwrap_or_else(|_| serde_json::json!(v));
            (k.to_string(), value)
        })
        .collect()
}

async fn call(
    client: &Client,
    tool: &str,
    args: serde_json::Map<String, serde_json::Value>,
) -> Result<String, ServiceError> {
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

fn truncate(s: &str) -> String {
    let flat = s.replace('\n', " ");
    flat.chars().take(56).collect::<String>().trim().to_string()
}

fn wrap(s: &str, width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut line = String::new();
    for word in s.split_whitespace() {
        if line.len() + word.len() + 1 > width && !line.is_empty() {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(' ');
        }
        line.push_str(word);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
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

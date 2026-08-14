//! Scripted live demo session, driven as a real MCP client against Customhouse.
//!
//! Run it through `./demo/run.sh`, which builds the binaries, points
//! `CUSTOMHOUSE_HOME` at a throwaway temp directory, and sets `CUSTOMHOUSE_BIN` /
//! `CUSTOMHOUSE_CONFIG`. This example spawns `customhouse serve` (which in turn spawns
//! the mock upstream), then runs a fixed sequence of calls and narrates each.
//!
//! Nothing here is faked: every line of output is a real response from the real
//! proxy. The denied call asserts it was actually blocked — if self-protection
//! ever regressed, this demo would panic rather than print a comforting lie.

use std::error::Error;

use rmcp::{
    model::CallToolRequestParams, service::ServiceError, transport::TokioChildProcess, ServiceExt,
};

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let bin = env_or("CUSTOMHOUSE_BIN", "target/release/customhouse");
    let config = env_or("CUSTOMHOUSE_CONFIG", "demo/customhouse.toml");
    let home = std::env::var("CUSTOMHOUSE_HOME")
        .expect("CUSTOMHOUSE_HOME must be set — run this via ./demo/run.sh");

    rule("Customhouse — a normal call routes through; a self-attack is blocked");

    // Connect to Customhouse. Spawning `customhouse serve` starts the proxy, which
    // spawns the mock upstream behind it; both inherit CUSTOMHOUSE_HOME.
    step(
        "initialize",
        "connecting to Customhouse (it is proxying the mock upstream)",
    );
    let mut command = tokio::process::Command::new(&bin);
    command.args(["serve", "--config", &config]);
    let client = ().serve(TokioChildProcess::new(command)?).await?;
    ok("connected; MCP protocol negotiated");

    // What does Customhouse expose? The upstream's tools, namespaced.
    step("tools/list", "what does Customhouse expose to the client?");
    for tool in client.list_all_tools().await? {
        ok(&format!(
            "{}   (the upstream's `echo`, namespaced by Customhouse)",
            tool.name
        ));
    }

    // A normal call: routes to the upstream and comes back.
    rule("ALLOWED: a normal call routes through to the upstream");
    let echoed = call_echo(&client, "hello through Customhouse").await?;
    ok(&format!("mock__echo returned: {echoed:?}"));

    // A self-attack: the model steers a tool at Customhouse's own ledger file.
    rule("DENIED: self-protection blocks a call targeting Customhouse's own files");
    let ledger_path = format!("{home}/ledger.jsonl");
    say(&format!(
        "the model asks mock__echo to touch Customhouse's own ledger:\n    {ledger_path}"
    ));
    match call_echo(&client, &ledger_path).await {
        Ok(_) => panic!("self-protection regressed: the attack was NOT blocked"),
        Err(ServiceError::McpError(error)) => {
            blocked(&format!(
                "blocked (JSON-RPC {}): {}",
                error.code.0, error.message
            ));
            say("the client is told nothing about which path — that detail goes only to the operator ledger.");
        }
        Err(other) => return Err(other.into()),
    }

    client.cancel().await?;
    Ok(())
}

/// Call `mock__echo` with a `text` argument and return the echoed text.
async fn call_echo(
    client: &rmcp::service::RunningService<rmcp::RoleClient, ()>,
    text: &str,
) -> Result<String, ServiceError> {
    let mut arguments = serde_json::Map::new();
    arguments.insert("text".into(), text.into());
    let result = client
        .call_tool(CallToolRequestParams::new("mock__echo").with_arguments(arguments))
        .await?;
    let echoed = result
        .content
        .first()
        .and_then(|block| block.as_text())
        .map(|text| text.text.clone())
        .unwrap_or_default();
    Ok(echoed)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn rule(title: &str) {
    println!("\n\u{2500}\u{2500} {title} \u{2500}\u{2500}");
}

fn step(method: &str, detail: &str) {
    println!("\n\u{25b6} {method} \u{2014} {detail}");
}

fn ok(detail: &str) {
    println!("  \u{2713} {detail}");
}

fn blocked(detail: &str) {
    println!("  \u{2717} {detail}");
}

fn say(detail: &str) {
    println!("    {detail}");
}

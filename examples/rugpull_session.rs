//! Scripted rug-pull demo, driven as a real MCP client against Penstock.
//!
//! Run it through `./demo/run_rugpull.sh`, which builds the binaries and points
//! `PENSTOCK_HOME` at a throwaway directory. Each "run" below spawns a fresh
//! `penstock serve`, because pin checking happens when Penstock connects to an
//! upstream — the pins persist across runs in the store.
//!
//! Nothing here is faked: the tool lists come from real `tools/list` responses
//! and the before/after diff is read out of the audit ledger Penstock wrote. The
//! withhold is asserted — if a mutated definition were ever served, this panics
//! rather than printing a comforting lie.

use std::error::Error;
use std::path::Path;

use rmcp::{transport::TokioChildProcess, ServiceExt};

type BoxError = Box<dyn Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let bin = env_or("PENSTOCK_BIN", "target/release/penstock");
    let config = env_or("PENSTOCK_CONFIG", "demo/penstock.toml");
    let home = std::env::var("PENSTOCK_HOME")
        .expect("PENSTOCK_HOME must be set — run this via ./demo/run_rugpull.sh");

    rule("Penstock rug-pull demo — a tool's definition silently changes");

    rule("Run 1 — first sight: Penstock pins mock's echo and serves it");
    let served = list_tools(&bin, &config, false).await?;
    say(&format!("tools/list: {served:?}"));

    rule("The upstream is swapped: echo's description now carries a prompt injection");

    rule("Run 2 — on reconnect, Penstock re-checks the definition and catches the change");
    let served = list_tools(&bin, &config, true).await?;
    say(&format!(
        "tools/list: {served:?}   <- the mutated tool is withheld, not served"
    ));
    assert!(
        served.is_empty(),
        "self-protection regressed: the mutated tool was served instead of withheld"
    );
    say("the audit ledger recorded the before/after the model would have seen:");
    print_withheld_diff(Path::new(&home).join("ledger.jsonl").as_path())?;

    rule("The operator reviews the diff and explicitly accepts the new definition");
    say("$ penstock repin mock");
    let status = std::process::Command::new(&bin)
        .args(["repin", "mock"])
        .status()?;
    if !status.success() {
        return Err("repin failed".into());
    }

    rule("Run 3 — with the change accepted, echo is served again");
    let served = list_tools(&bin, &config, false).await?;
    say(&format!("tools/list: {served:?}"));
    assert!(
        !served.is_empty(),
        "after an explicit repin the tool should be served again"
    );

    println!("\nPenstock never served the changed definition until a human accepted it.");
    Ok(())
}

/// Spawn one `penstock serve`, list what it exposes, and shut it down.
///
/// `rugpull` sets the mock upstream's mutation flag in the child's environment;
/// Penstock passes its environment to the upstream it spawns.
async fn list_tools(bin: &str, config: &str, rugpull: bool) -> Result<Vec<String>, BoxError> {
    let mut command = tokio::process::Command::new(bin);
    command.args(["serve", "--config", config]);
    if rugpull {
        command.env("MOCK_ECHO_RUGPULL", "1");
    }

    let client = ().serve(TokioChildProcess::new(command)?).await?;
    let tools = client
        .list_all_tools()
        .await?
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    client.cancel().await?;
    Ok(tools)
}

/// Print the pinned-vs-current descriptions from the ledger's withhold record —
/// the evidence an operator reviews before accepting a changed definition.
fn print_withheld_diff(ledger: &Path) -> Result<(), BoxError> {
    let contents = std::fs::read_to_string(ledger)?;
    for line in contents.lines() {
        let entry: serde_json::Value = serde_json::from_str(line)?;
        if entry["kind"] != "metadata" || entry["event"] != "withheld" {
            continue;
        }
        let Some(detail) = entry["detail"].as_str() else {
            continue;
        };
        // The ledger records `pinned=<canonical> current=<canonical>`.
        let Some((pinned, current)) = detail
            .strip_prefix("pinned=")
            .and_then(|rest| rest.split_once(" current="))
        else {
            continue;
        };
        println!("      pinned : {}", description_of(pinned));
        println!("      current: {}", description_of(current));
    }
    Ok(())
}

/// Pull the human-readable description out of a canonical tool definition.
fn description_of(canonical: &str) -> String {
    serde_json::from_str::<serde_json::Value>(canonical)
        .ok()
        .and_then(|value| value["description"].as_str().map(String::from))
        .unwrap_or_else(|| "<unreadable>".to_string())
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

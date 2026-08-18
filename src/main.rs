//! Customhouse binary entry point.
//!
//! `customhouse serve [--config <path>]` runs the aggregating MCP proxy over stdio;
//! `customhouse repin <server>` accepts an upstream's current tool definitions.
//! stdout carries the MCP protocol; diagnostics go to stderr.

use std::path::PathBuf;
use std::process::ExitCode;

use customhouse::approval::{self, ApprovalStore};
use customhouse::sink::SinkClass;
use customhouse::{Config, PinStore};

/// Config file consulted when `--config` is not given, if it exists.
const DEFAULT_CONFIG_PATH: &str = "customhouse.toml";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("{} {}", customhouse::name(), customhouse::version());
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            print_usage();
            ExitCode::SUCCESS
        }
        None | Some("serve") => run_serve(args.collect()),
        Some("repin") => run_repin(args.collect()),
        Some("approve") => run_approve(args.collect()),
        Some("verify-ledger") => run_verify_ledger(args.collect()),
        Some(other) => {
            eprintln!("customhouse: unknown argument `{other}`");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

/// `customhouse repin <server>` — forget a server's pins so its current tool
/// definitions are accepted (re-pinned fresh) on the next `serve`. Deliberately
/// minimal: it edits the pin store on disk and exits, a state change made
/// outside the mediated surface. No interactive approval protocol.
fn run_repin(rest: Vec<String>) -> ExitCode {
    let server = match rest.as_slice() {
        [server] => server,
        [] => {
            eprintln!("customhouse: repin requires a server name");
            print_usage();
            return ExitCode::FAILURE;
        }
        _ => {
            eprintln!("customhouse: repin takes exactly one server name");
            return ExitCode::FAILURE;
        }
    };

    let mut pins = PinStore::open();
    if !pins.forget_server(server) {
        // Not an error: nothing to accept is a perfectly fine outcome.
        eprintln!("customhouse: no pins found for server `{server}` (nothing to repin)");
        return ExitCode::SUCCESS;
    }
    match pins.save() {
        Ok(()) => {
            eprintln!(
                "customhouse: repinned `{server}` — its current definitions will be accepted on next serve"
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("customhouse: failed to save pin store: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run_serve(rest: Vec<String>) -> ExitCode {
    let (config, config_path) = match resolve_config(rest) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("customhouse: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("customhouse: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(customhouse::serve_stdio(config, config_path.as_deref())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("customhouse: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Parse `serve`'s arguments and load the resulting configuration, returning it
/// alongside the path it was loaded from (if any) so the path can be protected.
fn resolve_config(rest: Vec<String>) -> Result<(Config, Option<PathBuf>), String> {
    let mut explicit_path: Option<PathBuf> = None;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" | "-c" => {
                let path = args
                    .next()
                    .ok_or_else(|| "--config requires a path".to_string())?;
                explicit_path = Some(PathBuf::from(path));
            }
            other => return Err(format!("unknown argument `{other}`")),
        }
    }

    // An explicit path must exist; the default path is used only if present.
    let path = match explicit_path {
        Some(path) => Some(path),
        None => match PathBuf::from(DEFAULT_CONFIG_PATH) {
            path if path.exists() => Some(path),
            _ => None,
        },
    };

    let config = Config::load(path.as_deref()).map_err(|e| e.to_string())?;
    Ok((config, path))
}

/// `customhouse approve <sink-class>` — authorise one retry of a sink class that
/// flow policy escalated. Deliberately out-of-band: the agent cannot reach this
/// command, and §3 stops it writing the store directly.
fn run_approve(rest: Vec<String>) -> ExitCode {
    let classes = SinkClass::all()
        .iter()
        .map(|c| c.as_str())
        .collect::<Vec<_>>()
        .join(", ");

    let name = match rest.as_slice() {
        [name] => name.clone(),
        _ => {
            eprintln!("customhouse: approve requires exactly one sink class ({classes})");
            return ExitCode::FAILURE;
        }
    };
    let Some(class) = SinkClass::parse(&name) else {
        eprintln!("customhouse: unknown sink class `{name}` (expected one of: {classes})");
        return ExitCode::FAILURE;
    };

    let mut store = ApprovalStore::open();
    store.grant(class, approval::now_ms());
    match store.save() {
        Ok(()) => {
            eprintln!(
                "customhouse: approved one {} call. It is single-use and expires in {} minutes.",
                class.as_str(),
                approval::VALIDITY_MS / 60_000
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("customhouse: failed to save approval: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `customhouse verify-ledger [path]` — walk the ledger's hash chain.
///
/// Reports tampering in the sense of a point edit; it does not attest who wrote
/// the entries. See SECURITY.md for what that does and does not buy.
fn run_verify_ledger(rest: Vec<String>) -> ExitCode {
    let path = match rest.as_slice() {
        [] => customhouse::paths::customhouse_home().join("ledger.jsonl"),
        [p] => PathBuf::from(p),
        _ => {
            eprintln!("customhouse: verify-ledger takes at most one path");
            return ExitCode::FAILURE;
        }
    };
    match customhouse::ledger::verify(&path) {
        Ok(n) => {
            eprintln!(
                "customhouse: {} entries verified; the chain is intact from the genesis entry.",
                n
            );
            eprintln!("customhouse: this detects edited or removed entries. It does not prove who wrote them.");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("customhouse: ledger verification FAILED");
            eprintln!("  {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("Usage: customhouse <command> [options]");
    eprintln!("  serve [--config <path>]   Run the aggregating MCP proxy over stdio (default;");
    eprintln!("                            config default: customhouse.toml)");
    eprintln!("  repin <server>            Accept an upstream's current tool definitions");
    eprintln!("  approve <sink-class>      Authorise one retry of an escalated sink call");
    eprintln!("  verify-ledger [path]      Walk the audit ledger's hash chain");
    eprintln!("  --version | --help");
}

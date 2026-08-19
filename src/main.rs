//! Customhouse binary entry point.
//!
//! `customhouse serve [--config <path>]` runs the aggregating MCP proxy over stdio;
//! `customhouse repin <server>` accepts an upstream's current tool definitions.
//! stdout carries the MCP protocol; diagnostics go to stderr.

use std::path::PathBuf;
use std::process::ExitCode;

use customhouse::approval::{self, ApprovalStore};
use customhouse::sink::SinkClass;
use customhouse::{init, Config, PinStore};

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
        Some("init") => run_init(args.collect()),
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

/// `customhouse init [--config <path>] [--force]` — write a starting config from
/// the MCP servers an agent client already launches.
///
/// Reports what it found, what it skipped and why, and what the user still has
/// to decide. It never asserts trust; see `init`'s module docs for why a
/// generated file that guessed would be worse than no file.
fn run_init(rest: Vec<String>) -> ExitCode {
    let mut out_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut force = false;
    let mut args = rest.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--force" | "-f" => force = true,
            "--config" | "-c" => match args.next() {
                Some(path) => out_path = PathBuf::from(path),
                None => {
                    eprintln!("customhouse: --config requires a path");
                    return ExitCode::FAILURE;
                }
            },
            other => {
                eprintln!("customhouse: unknown argument `{other}`");
                return ExitCode::FAILURE;
            }
        }
    }

    // Checked before any reading, so a run that cannot write says so straight
    // away rather than after printing a discovery report the user cannot use.
    if out_path.exists() && !force {
        eprintln!(
            "customhouse: {} already exists. Move it aside, or pass --force to overwrite it.",
            out_path.display()
        );
        return ExitCode::FAILURE;
    }

    let mut discovery = init::Discovery::default();
    let mut read_any = false;
    for candidate in init::candidate_paths() {
        let Ok(text) = std::fs::read_to_string(&candidate) else {
            continue; // A client that is not installed is not a problem.
        };
        read_any = true;
        let label = candidate.display().to_string();
        eprintln!("customhouse: reading {label}");
        if let Err(e) = discovery.absorb(&label, &text) {
            eprintln!("customhouse: skipping {label}: {e}");
        }
    }
    if !read_any {
        eprintln!("customhouse: found no agent client configs in the usual locations.");
        eprintln!("customhouse: writing a template you can fill in.");
    }

    let rendered = init::render_toml(&discovery);
    if let Err(e) = std::fs::write(&out_path, &rendered) {
        eprintln!("customhouse: cannot write {}: {e}", out_path.display());
        return ExitCode::FAILURE;
    }

    for server in &discovery.servers {
        eprintln!("  + {} ({})", server.name, server.command);
    }
    for skipped in &discovery.skipped {
        eprintln!("  - {}: {}", skipped.name, skipped.reason.explain());
    }

    eprintln!("customhouse: wrote {}", out_path.display());
    eprintln!(
        "customhouse: every upstream is UNTRUSTED. Until you edit that, any session
            that reads from one is tainted and sink calls are refused or escalated."
    );
    eprintln!("customhouse: review the file, then run `customhouse serve`.");
    ExitCode::SUCCESS
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
    eprintln!("  init [--config <path>]    Write a starting config from your agent client's");
    eprintln!("                            MCP servers (--force to overwrite)");
    eprintln!("  repin <server>            Accept an upstream's current tool definitions");
    eprintln!("  approve <sink-class>      Authorise one retry of an escalated sink call");
    eprintln!("  verify-ledger [path]      Walk the audit ledger's hash chain");
    eprintln!("  --version | --help");
}

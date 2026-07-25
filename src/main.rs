//! Bulkhead binary entry point.
//!
//! `bulkhead serve [--config <path>]` runs the aggregating MCP proxy over stdio.
//! stdout carries the MCP protocol; diagnostics go to stderr.

use std::path::PathBuf;
use std::process::ExitCode;

use bulkhead::Config;

/// Config file consulted when `--config` is not given, if it exists.
const DEFAULT_CONFIG_PATH: &str = "bulkhead.toml";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);

    match args.next().as_deref() {
        Some("--version" | "-V") => {
            println!("{} {}", bulkhead::name(), bulkhead::version());
            ExitCode::SUCCESS
        }
        Some("--help" | "-h") => {
            print_usage();
            ExitCode::SUCCESS
        }
        None | Some("serve") => run_serve(args.collect()),
        Some(other) => {
            eprintln!("bulkhead: unknown argument `{other}`");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn run_serve(rest: Vec<String>) -> ExitCode {
    let (config, config_path) = match resolve_config(rest) {
        Ok(loaded) => loaded,
        Err(e) => {
            eprintln!("bulkhead: {e}");
            return ExitCode::FAILURE;
        }
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("bulkhead: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(bulkhead::serve_stdio(config, config_path.as_deref())) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bulkhead: {e}");
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

fn print_usage() {
    eprintln!("Usage: bulkhead [serve [--config <path>] | --version | --help]");
    eprintln!("  serve   Run the aggregating MCP proxy over stdio (default)");
    eprintln!("  --config <path>   Upstream servers to aggregate (default: bulkhead.toml)");
}

//! Bulkhead binary entry point.
//!
//! `bulkhead serve` (or no argument) runs the aggregating MCP proxy over stdio.
//! stdout carries the MCP protocol; diagnostics go to stderr.

use std::process::ExitCode;

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
        None | Some("serve") => run_serve(),
        Some(other) => {
            eprintln!("bulkhead: unknown argument `{other}`");
            print_usage();
            ExitCode::FAILURE
        }
    }
}

fn run_serve() -> ExitCode {
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("bulkhead: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };

    eprintln!("bulkhead {}: serving MCP proxy on stdio", bulkhead::version());
    match runtime.block_on(bulkhead::serve_stdio()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("bulkhead: {e}");
            ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    eprintln!("Usage: bulkhead [serve | --version | --help]");
    eprintln!("  serve   Run the aggregating MCP proxy over stdio (default)");
}

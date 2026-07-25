//! Bulkhead binary entry point.
//!
//! Chunk 0: a process that starts and reports its version. The MCP stdio server
//! is wired in chunk 1.

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
        Some(other) => {
            eprintln!("bulkhead: unknown argument `{other}`");
            print_usage();
            ExitCode::FAILURE
        }
        None => {
            // No subcommand yet; the proxy server lands in chunk 1.
            eprintln!("bulkhead {}: MCP proxy not yet implemented (chunk 0)", bulkhead::version());
            ExitCode::SUCCESS
        }
    }
}

fn print_usage() {
    eprintln!("Usage: bulkhead [--version | --help]");
}

#!/usr/bin/env bash
# One-command Bulkhead demo. Builds the binaries, runs a real MCP session against
# the proxy, and prints the audit ledger the session produced. Hermetic: uses a
# throwaway BULKHEAD_HOME, so it never touches your real ~/.bulkhead.
set -euo pipefail

# Run from the repo root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

echo "Building bulkhead (release)…"
cargo build --release --quiet

# A fresh, throwaway home so the demo is repeatable and touches no real state.
DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export BULKHEAD_HOME="$DEMO_ROOT/bulkhead-home"
export BULKHEAD_BIN="target/release/bulkhead"
export BULKHEAD_CONFIG="demo/bulkhead.toml"

# Drive the scripted session (a real MCP client; see examples/demo_session.rs).
cargo run --release --quiet --example demo_session

# Show the audit trail the session just wrote.
printf '\n── The audit trail (%s) ──\n' "$BULKHEAD_HOME/ledger.jsonl"
cat "$BULKHEAD_HOME/ledger.jsonl"
printf '\nNote: the deny line carries the operator-only "detail" path; the client never saw it.\n'

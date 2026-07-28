#!/usr/bin/env bash
# One-command Penstock demo. Builds the binaries, runs a real MCP session against
# the proxy, and prints the audit ledger the session produced. Hermetic: uses a
# throwaway PENSTOCK_HOME, so it never touches your real ~/.penstock.
set -euo pipefail

# Run from the repo root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

echo "Building penstock (release)…"
cargo build --release --quiet

# A fresh, throwaway home so the demo is repeatable and touches no real state.
DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export PENSTOCK_HOME="$DEMO_ROOT/penstock-home"
export PENSTOCK_BIN="target/release/penstock"
export PENSTOCK_CONFIG="demo/penstock.toml"

# Drive the scripted session (a real MCP client; see examples/demo_session.rs).
cargo run --release --quiet --example demo_session

# Show the audit trail the session just wrote.
printf '\n── The audit trail (%s) ──\n' "$PENSTOCK_HOME/ledger.jsonl"
cat "$PENSTOCK_HOME/ledger.jsonl"
printf '\nNote: the deny line carries the operator-only "detail" path; the client never saw it.\n'

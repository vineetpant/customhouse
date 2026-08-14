#!/usr/bin/env bash
# One-command Customhouse demo. Builds the binaries, runs a real MCP session against
# the proxy, and prints the audit ledger the session produced. Hermetic: uses a
# throwaway CUSTOMHOUSE_HOME, so it never touches your real ~/.customhouse.
set -euo pipefail

# Run from the repo root regardless of where the script is invoked from.
cd "$(dirname "$0")/.."

echo "Building customhouse (release)…"
cargo build --release --quiet

# A fresh, throwaway home so the demo is repeatable and touches no real state.
DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export CUSTOMHOUSE_HOME="$DEMO_ROOT/customhouse-home"
export CUSTOMHOUSE_BIN="target/release/customhouse"
export CUSTOMHOUSE_CONFIG="demo/customhouse.toml"

# Drive the scripted session (a real MCP client; see examples/demo_session.rs).
cargo run --release --quiet --example demo_session

# Show the audit trail the session just wrote.
printf '\n── The audit trail (%s) ──\n' "$CUSTOMHOUSE_HOME/ledger.jsonl"
cat "$CUSTOMHOUSE_HOME/ledger.jsonl"
printf '\nNote: the deny line carries the operator-only "detail" path; the client never saw it.\n'

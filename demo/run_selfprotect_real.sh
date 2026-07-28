#!/usr/bin/env bash
# Penstock self-protection, proven against a REAL MCP server rather than the
# bundled mock: the official @modelcontextprotocol/server-filesystem.
#
# PENSTOCK_HOME is deliberately placed inside the directory that server is
# allowed to access, so it genuinely can read the ledger and overwrite the pin
# store. Only the compiled-in invariant gate prevents it. The session asserts
# every outcome and exits non-zero if a refusal ever turns into a success.
#
# Requires: Rust toolchain, and Node (npx fetches the server on first run).
# Everything else — ./demo/run.sh and ./demo/run_rugpull.sh — needs only Rust.
set -euo pipefail
cd "$(dirname "$0")/.."

if ! command -v npx >/dev/null 2>&1; then
    echo "This demo needs Node (npx) to fetch the real MCP filesystem server." >&2
    echo "Install Node, or run ./demo/run.sh which needs only the Rust toolchain." >&2
    exit 127
fi

echo "Building penstock (release)…"
cargo build --release --quiet

DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT

# The server's allowed directory. Penstock's own state lives inside it — that is
# the point of this demo, not an oversight.
SANDBOX="$DEMO_ROOT/sandbox"
mkdir -p "$SANDBOX"
echo "an ordinary file the agent is entitled to read" > "$SANDBOX/note.txt"

export PENSTOCK_HOME="$SANDBOX/penstock-home"
export PENSTOCK_BIN="target/release/penstock"
export PENSTOCK_CONFIG="$DEMO_ROOT/penstock.toml"
export PENSTOCK_DEMO_FILE="$SANDBOX/note.txt"

cat > "$PENSTOCK_CONFIG" <<EOF
[[upstream]]
name = "fs"
command = "npx"
args = ["-y", "@modelcontextprotocol/server-filesystem", "$SANDBOX"]
EOF

cargo run --release --quiet --example real_server_session

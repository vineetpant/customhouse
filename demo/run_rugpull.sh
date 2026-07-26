#!/usr/bin/env bash
# Bulkhead rug-pull demo: an upstream silently changes a tool's definition
# between runs, and Bulkhead withholds it until an operator accepts the change.
# Hermetic: a throwaway BULKHEAD_HOME, never touches your real ~/.bulkhead.
# Needs only the Rust toolchain — the session itself is examples/rugpull_session.rs.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building bulkhead (release)…"
cargo build --release --quiet

DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export BULKHEAD_HOME="$DEMO_ROOT/home"
export BULKHEAD_BIN="target/release/bulkhead"
export BULKHEAD_CONFIG="demo/bulkhead.toml"

cargo run --release --quiet --example rugpull_session

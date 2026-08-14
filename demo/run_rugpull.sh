#!/usr/bin/env bash
# Customhouse rug-pull demo: an upstream silently changes a tool's definition
# between runs, and Customhouse withholds it until an operator accepts the change.
# Hermetic: a throwaway CUSTOMHOUSE_HOME, never touches your real ~/.customhouse.
# Needs only the Rust toolchain — the session itself is examples/rugpull_session.rs.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building customhouse (release)…"
cargo build --release --quiet --bin customhouse --example mock_upstream --example mock_sink

DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export CUSTOMHOUSE_HOME="$DEMO_ROOT/home"
export CUSTOMHOUSE_BIN="target/release/customhouse"
export CUSTOMHOUSE_CONFIG="demo/customhouse.toml"

cargo run --release --quiet --example rugpull_session

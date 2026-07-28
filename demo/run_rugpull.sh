#!/usr/bin/env bash
# Penstock rug-pull demo: an upstream silently changes a tool's definition
# between runs, and Penstock withholds it until an operator accepts the change.
# Hermetic: a throwaway PENSTOCK_HOME, never touches your real ~/.penstock.
# Needs only the Rust toolchain — the session itself is examples/rugpull_session.rs.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building penstock (release)…"
cargo build --release --quiet

DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export PENSTOCK_HOME="$DEMO_ROOT/home"
export PENSTOCK_BIN="target/release/penstock"
export PENSTOCK_CONFIG="demo/penstock.toml"

cargo run --release --quiet --example rugpull_session

#!/usr/bin/env bash
# Measures the flow rule: block rate against injection scenarios, false-positive
# rate against benign work. Writes METRICS.md. Needs only the Rust toolchain.
set -euo pipefail
cd "$(dirname "$0")/.."
DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export PENSTOCK_HOME="$DEMO_ROOT/home"
cargo run --release --quiet --example metrics

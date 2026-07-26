#!/usr/bin/env bash
# Bulkhead rug-pull demo: an upstream silently changes a tool's definition
# between runs, and Bulkhead withholds it until an operator accepts the change.
# Hermetic: a throwaway BULKHEAD_HOME, never touches your real ~/.bulkhead.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "Building bulkhead (release)…"
cargo build --release --quiet

DEMO_ROOT="$(mktemp -d)"
trap 'rm -rf "$DEMO_ROOT"' EXIT
export BULKHEAD_HOME="$DEMO_ROOT/home"
BIN="target/release/bulkhead"
CONFIG="demo/bulkhead.toml"

init='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}'
inited='{"jsonrpc":"2.0","method":"notifications/initialized"}'
list='{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'

# Drive one serve invocation, print the tools it exposes; stderr -> $1.
list_tools() {
    printf '%s\n' "$init" "$inited" "$list" | "$BIN" serve --config "$CONFIG" 2>"$1" \
        | python3 -c "import sys,json;[print([t['name'] for t in json.loads(l).get('result',{}).get('tools',[])]) for l in sys.stdin if l.strip() and json.loads(l).get('id')==2]"
}

rule() { printf '\n── %s ──\n' "$1"; }

rule "Bulkhead rug-pull demo — a tool's definition silently changes"

rule "Run 1 — first sight: Bulkhead pins mock's echo and serves it"
echo "  tools/list: $(list_tools "$DEMO_ROOT/e1")"
grep -i "pinned" "$DEMO_ROOT/e1" | sed 's/^/  /' || true

rule "The upstream is swapped: echo's description now carries a prompt injection"
export MOCK_ECHO_RUGPULL=1

rule "Run 2 — on reconnect, Bulkhead re-checks the definition and catches the change"
run2_tools="$(list_tools "$DEMO_ROOT/e2")"
echo "  tools/list: $run2_tools   ← the mutated tool is withheld, not served"
grep -i "WITHHELD" "$DEMO_ROOT/e2" | sed 's/^/  /' || true
if [ "$run2_tools" != "[]" ]; then
    echo "DEMO FAILED: the mutated tool was served instead of withheld." >&2
    exit 1
fi
echo "  the audit ledger recorded the before/after the model would have seen:"
python3 - "$BULKHEAD_HOME/ledger.jsonl" <<'PY'
import sys, json
for line in open(sys.argv[1]):
    e = json.loads(line)
    if e.get("kind") == "metadata" and e.get("event") == "withheld":
        d = e.get("detail", "")
        pinned = d.split("pinned=", 1)[1].split(" current=", 1)[0]
        current = d.split(" current=", 1)[1]
        print("    pinned : ", json.loads(pinned).get("description"))
        print("    current: ", json.loads(current).get("description"))
PY

rule "The operator reviews the diff and explicitly accepts the new definition"
echo "  \$ bulkhead repin mock"
"$BIN" repin mock 2>&1 | sed 's/^/  /'

rule "Run 3 — with the change accepted, echo is served again"
echo "  tools/list: $(list_tools "$DEMO_ROOT/e3")"

printf '\nBulkhead never served the changed definition until a human accepted it.\n'

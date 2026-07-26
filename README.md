# Bulkhead

Deterministic enforcement at the MCP tool boundary.

Most agent security is **antivirus**: it scans for bad stuff before you install a
tool. Bulkhead is the **firewall**: it sits in the live traffic and enforces the
rule that untrusted input can't drive sensitive output.

Bulkhead is an aggregating proxy that sits between an agent client and its
upstream MCP servers, acting as a deterministic reference monitor. Its hard
constraint: **no LLM/model call and no network access exists anywhere in the
enforcement path — policy evaluation is a pure function.**

See [`DESIGN-v2.md`](./DESIGN-v2.md) for the full design and threat model.

## See it in 30 seconds

```sh
git clone <this-repo> && cd bulkhead
./demo/run.sh
```

A real MCP session runs against the proxy (no faked output). Bulkhead routes a
normal call, then blocks one that targets its own files, and prints the audit
ledger it produced (temp paths abbreviated below):

```
── ALLOWED: a normal call routes through to the upstream ──
  ✓ mock__echo returned: "hello through Bulkhead"

── DENIED: self-protection blocks a call targeting Bulkhead's own files ──
    the model asks mock__echo to touch Bulkhead's own ledger:
    $BULKHEAD_HOME/ledger.jsonl
  ✗ blocked (JSON-RPC -32602): denied by Bulkhead self-protection: operation resolves onto Bulkhead's own files
    the client is told nothing about which path — that detail goes only to the operator ledger.

── The audit trail ($BULKHEAD_HOME/ledger.jsonl) ──
{"kind":"metadata","id":0,"ts_ms":...,"server":"mock","tool":"mock__echo","event":"pinned"}
{"kind":"call","id":1,"ts_ms":...,"tool":"mock__echo","server":"mock","decision":"allow"}
{"kind":"call","id":2,"ts_ms":...,"tool":"mock__echo","server":"mock","decision":"deny","detail":"$BULKHEAD_HOME/ledger.jsonl"}
```

The denied call is asserted, not narrated: if self-protection regressed, the demo
panics rather than printing a comforting lie. See [`demo/`](./demo).

### And a rug pull, blocked

```sh
./demo/run_rugpull.sh
```

Bulkhead pins a tool's definition, the upstream swaps that description to carry a
prompt injection, and Bulkhead **withholds** the changed tool — printing the real
before/after from its ledger — until an operator runs `bulkhead repin <server>`
to accept it. It never serves the pinned definition while the upstream would
execute the new one.

## Status

**Phase 0 complete** (v0.1.0): the aggregating proxy with tool namespacing,
compiled-in self-protection invariants, an append-only audit ledger, and metadata
pinning (rug-pull blocking with operator re-pin). Policy is otherwise passthrough.
Next: the Phase 1 taint/provenance model and tiered policy engine.

## Build

```sh
cargo build
cargo test
```

## License

Apache-2.0. See [`LICENSE`](./LICENSE).

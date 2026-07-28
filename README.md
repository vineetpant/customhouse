# Penstock

**Deterministic enforcement at the MCP tool boundary.**

Most agent security is **antivirus**: it scans for bad stuff before you install a
tool. Penstock is the **firewall**: it sits in the live traffic between an agent
and its tools, and enforces rules there.

> **Scope, up front:** v0.1.0 gives you observability, self-protection, and
> rug-pull detection. The flow-enforcement rule that stops untrusted input from
> reaching a sensitive sink is **on the roadmap, not in this release.** See
> [Roadmap](#roadmap) and [`SECURITY.md`](./SECURITY.md).

## See it in 30 seconds

Needs only a [Rust toolchain](https://rustup.rs) (1.92+). No other dependencies —
the demo builds and runs everything itself, in a throwaway directory.

```sh
git clone https://github.com/vineetpant/penstock && cd penstock
./demo/run.sh
```

A real MCP session runs against the proxy. Nothing below is mocked up for the
README — it is the actual output, with temp paths shortened:

```
── ALLOWED: a normal call routes through to the upstream ──
  ✓ mock__echo returned: "hello through Penstock"

── DENIED: self-protection blocks a call targeting Penstock's own files ──
    the model asks mock__echo to touch Penstock's own ledger:
    $PENSTOCK_HOME/ledger.jsonl
  ✗ blocked (JSON-RPC -32602): denied by Penstock self-protection: operation resolves onto Penstock's own files
    the client is told nothing about which path — that detail goes only to the operator ledger.

── The audit trail ($PENSTOCK_HOME/ledger.jsonl) ──
{"kind":"metadata","id":0,"ts_ms":1785103954479,"server":"mock","tool":"mock__echo","event":"pinned"}
{"kind":"call","id":1,"ts_ms":1785103954481,"tool":"mock__echo","server":"mock","decision":"allow"}
{"kind":"call","id":2,"ts_ms":1785103954482,"tool":"mock__echo","server":"mock","decision":"deny","detail":"$PENSTOCK_HOME/ledger.jsonl"}
```

The denial is asserted, not narrated: if self-protection regressed, the demo
fails instead of printing a comforting lie.

**A rug pull, blocked** — `./demo/run_rugpull.sh` pins a tool's definition, lets
the upstream swap that description for a prompt injection, and shows Penstock
withholding the changed tool (printing the real before/after from its ledger)
until you run `penstock repin <server>`.

## What it does today

**Observability.** Penstock aggregates your MCP servers behind one endpoint and
writes an append-only JSONL ledger of every mediated call — which tool, which
upstream, what was decided. Useful on its own: it is a flight recorder for what
your agent's tools actually did.

**Self-protection.** A set of invariants compiled into the binary — not
configurable, not reachable through the proxied surface — denies any call whose
arguments resolve onto Penstock's own files: its home directory, its ledger and
pin store, its binary, its config. Paths are canonicalized first (symlinks, `..`,
`~`), so the check runs on the resolved target rather than the argument string.
This is what stops an agent from being steered into disarming the thing watching
it.

**Rug-pull detection (R1).** Tool descriptions and schemas are attacker-controlled
text that lands directly in your model's context. Penstock pins each tool
definition on first sight and, on reconnect, withholds any tool whose definition
changed — it will not serve the old definition while the upstream would execute
the new one. Restoring it takes an explicit `penstock repin <server>`, after you
have seen the diff.

## Roadmap

**Not yet built — flow enforcement (R3).** The rule the architecture exists for:
*untrusted-derived data must not reach an exfiltration sink*. Taint labelling,
provenance matching, sink tiering, and the consent/escalation path are Phase 1.
**v0.1.0 does not defend against prompt-injection-driven exfiltration.** If that
is what you need today, this release is not it.

**Also ahead:** capability profiles confining each server by effect and argument
shape (R2); mediation extended beyond tools to resources and prompts; and
**Phase 2 benchmarks** — AgentDojo attack-success *and* task-utility numbers,
published side by side, because a measured mediocre result is credible and an
unmeasured strong claim is not.

## How it works

Penstock is an **aggregating proxy**: it presents to your client as a single MCP
server and multiplexes N upstreams behind it, namespacing their tools
(`web__fetch`, `mail__send`). That shape is the design's central bet. The attack
worth stopping is a *cross-server flow* — content read through one server,
exfiltrated through another — and each individual call in that flow is
permitted. A per-server sidecar structurally cannot see the flow, because it only
ever sees its own half. One chokepoint can.

The second commitment is **determinism**: no model call, no network request, and
no nondeterminism anywhere in the decision path. Policy evaluation is a pure
function of the request and local state. This matters because the thing being
defended against is a model that has been talked into something — so asking
another model whether a call is safe reintroduces the vulnerability at the point
it was meant to be removed. It also means decisions are reproducible, auditable,
and testable, which is why the enforcement path is exercised by unit tests and
two self-asserting demos rather than by vibes.

## Prior art, and what is different here

Penstock is not the first attempt to put a control point between an agent and
its tools. Adjacent work includes **Scandar**, which tracks taint through content
fingerprints, and **Agent Shield**, which uses a proxy placement similar to this
one. Both are worth your attention, and where the ideas overlap that is
convergence on a sensible design, not novelty here.

The narrower claim: Penstock is **open source, aggregating** (one chokepoint
across all servers rather than one guard per server), **deterministic** (no model
anywhere in the enforcement path), **inline** (decisions happen before a call is
forwarded, not in a report afterwards), and mediates **both directions** — what
reaches the model, including tool metadata, as well as what leaves it. Every one
of those is a design choice with costs, and they are argued in
[`DESIGN-v2.md`](./DESIGN-v2.md).

## Install

Build from source:

```sh
git clone https://github.com/vineetpant/penstock && cd penstock
cargo build --release      # binary at target/release/penstock
cargo test
```

Point Penstock at your MCP servers with a `penstock.toml`:

```toml
[[upstream]]
name = "web"                     # namespaces its tools as web__*
command = "/path/to/web-mcp-server"
args = ["--stdio"]

[[upstream]]
name = "mail"
command = "/path/to/mail-mcp-server"
```

Then point your MCP client at Penstock instead of at those servers directly:

```json
{
  "mcpServers": {
    "penstock": {
      "command": "/path/to/penstock",
      "args": ["serve", "--config", "/path/to/penstock.toml"]
    }
  }
}
```

State (ledger, pins) lives in `$PENSTOCK_HOME`, default `~/.penstock`.
Run `penstock --help` for the full CLI.

## Documentation

- [`DESIGN-v2.md`](./DESIGN-v2.md) — full design and threat model
- [`SECURITY.md`](./SECURITY.md) — what v0.1.0 defends against, what it does not,
  and the limitations that will not be closed (with reasons)

## License

Apache-2.0. See [`LICENSE`](./LICENSE).

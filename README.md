# Penstock

**Deterministic enforcement at the MCP tool boundary.**

Most agent security is **antivirus**: it scans for bad stuff before you install a
tool. Penstock is the **firewall**: it sits in the live traffic between an agent
and its tools, and enforces rules there.

> **Scope, up front:** v0.1.0 gives you observability, self-protection, and
> rug-pull detection. The flow-enforcement rule that stops untrusted input from
> reaching a sensitive sink is **on the roadmap, not in this release.** See
> [Roadmap](#roadmap) and [`SECURITY.md`](./SECURITY.md).

## See it stop a real attack

An agent talked into disabling its own guardrail is not hypothetical — it is
[what happened to GitHub Copilot](https://www.microsoft.com/en-us/security/blog/2026/06/30/securing-ai-agents-ai-tools-move-from-reading-acting/),
where the guardrail lived *inside* the agent, so the agent could remove it.

This demo runs the **official `@modelcontextprotocol/server-filesystem`** — real
software, real permissions — and puts Penstock's own state *inside the directory
that server is allowed to access*. The server can genuinely read the ledger and
overwrite the pin store. Only the compiled-in gate stands in the way.

```sh
./demo/run_selfprotect_real.sh      # needs Node; the others need only Rust
```

Actual output, temp paths shortened:

```
── Penstock vs a real MCP server (@modelcontextprotocol/server-filesystem) ──
  14 tools aggregated and pinned from the real server

── ALLOWED: an ordinary file read passes straight through ──
  ✓ fs__read_text_file -> "an ordinary file the agent is entitled to read"

── DENIED: the agent tries to read Penstock's own audit ledger ──
  $PENSTOCK_HOME/ledger.jsonl
  ✗ refused (-32602): denied by Penstock self-protection: operation resolves onto Penstock's own files

── DENIED: the agent tries to overwrite Penstock's pin store ──
  $PENSTOCK_HOME/pins.json
  ✗ refused (-32602): denied by Penstock self-protection: operation resolves onto Penstock's own files

A real filesystem server, holding real permissions over these files,
was refused both times — and the refusals are in the ledger it could not read.
```

Every outcome is **asserted**. If self-protection regressed, the demo exits
non-zero rather than printing something reassuring.

### The other two demos

Both need only a [Rust toolchain](https://rustup.rs) (1.92+) — no other
dependencies, everything runs in a throwaway directory.

```sh
git clone https://github.com/vineetpant/penstock && cd penstock
./demo/run.sh            # allow, self-protection deny, and the audit ledger
./demo/run_rugpull.sh    # a poisoned tool definition, withheld until re-pinned
```

**The rug pull one matters.** `postmark-mcp` shipped
[fifteen clean versions before adding a line of exfiltration code](https://www.upguard.com/blog/mcp-security-incidents).
`run_rugpull.sh` reproduces that shape: Penstock pins a tool's definition, the
upstream swaps the description for a prompt injection, and Penstock **withholds**
the changed tool — printing the real before/after out of its ledger — until you
run `penstock repin <server>`. It never serves the old definition while the
upstream would execute the new one.

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
its tools.

[pipelock](https://github.com/luckyPipewrench/pipelock),
[ressl/mcp-firewall](https://github.com/ressl/mcp-firewall) and
[preloop](https://github.com/preloop/preloop) occupy adjacent ground. Where
designs converge, that is a sign the problem is real.

Three things are genuinely different here, and each has a cost:

- **Structural, not signature-based.** Every tool above detects badness *in
  content* via maintained pattern lists — 32 injection patterns here, 50+ there,
  65 DLP signatures. Penstock refuses that approach entirely. Nothing judges what
  content *says*; decisions rest on provenance and integrity — where data came
  from, where it is going, whether a definition changed. **The cost:** signatures
  catch known payloads that structure alone may wave through. This is a genuine
  disagreement about how agent security should work, and Phase 2's benchmarks
  exist to settle it with numbers rather than argument.
- **Aggregating, not per-server.** Those proxies wrap one upstream per instance.
  A cross-server flow — read through one server, exfiltrate through another — is
  structurally invisible to that placement. One chokepoint can see it. **The
  cost:** a single point of failure, and every server behind one config.
- **Fully Apache-2.0.** No open-core tier, no license key, no source-available
  enterprise split. For something sitting in the enforcement path, "you can read
  and fork all of it" is a security property. **The cost:** no commercial
  engine behind it.

All three are argued, with their trade-offs, in [`DESIGN-v2.md`](./DESIGN-v2.md).

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
